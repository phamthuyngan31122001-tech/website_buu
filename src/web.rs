use std::{
    collections::{HashMap, HashSet},
    fs,
    io::Cursor,
    net::{IpAddr, SocketAddr},
    path::{Path as StdPath, PathBuf},
    sync::{Arc, OnceLock},
};

use anyhow::{Context, anyhow};
use axum::{
    Json, Router,
    extract::{ConnectInfo, Form, Multipart, Path, Query, Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use calamine::{Data, Reader, open_workbook_auto_from_rs};
use chrono::{DateTime, Datelike, Duration, Utc};
use maud::{DOCTYPE, Markup, PreEscaped, html};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use tower_http::compression::CompressionLayer;
use tracing::{error, info};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt};

use crate::{
    crypto::{MasterKey, hash_password, random_token, verify_password},
    hybird::{
        decrypt_document, encrypt_document, encrypt_transport_payload as encrypt_sync_payload,
        load_or_create_kem_pair,
    },
    models::{
        Activity, ActivityStatus, AppData, Document, Member, Organization, User,
        UserRole, ancestor_ids, descendant_ids, new_id, now_string,
    },
    storage::Storage,
    tree_policy::{
        can_upload_documents, default_org_user_credentials, default_root_admin_credentials,
        direct_children, is_legacy_demo_document, is_shared_document, org_sort_key,
    },
};

#[derive(Clone)]
struct SessionState {
    user_id: String,
    csrf_token: String,
    unlocked_document_orgs: HashSet<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NetworkMode {
    InternetTest,
    LanOnly,
}

impl NetworkMode {
    fn from_env() -> Self {
        match std::env::var("APP_NETWORK_MODE")
            .unwrap_or_else(|_| "lan-only".to_owned())
            .to_ascii_lowercase()
            .as_str()
        {
            "internet" | "internet-test" | "internet_test" => Self::InternetTest,
            _ => Self::LanOnly,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::InternetTest => "internet-test",
            Self::LanOnly => "lan-only",
        }
    }

    fn from_control_value(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "internet" | "internet-test" | "internet_test" => Some(Self::InternetTest),
            "lan" | "lan-only" | "lan_only" => Some(Self::LanOnly),
            _ => None,
        }
    }
}

#[derive(Clone)]
struct AppConfig {
    bind_addr: String,
    tree_admin_key: String,
    kem_public_key: String,
    require_https: bool,
}

#[derive(Clone)]
struct NetworkSettings {
    mode: NetworkMode,
    ip_whitelist: Vec<IpAddr>,
}

#[derive(Clone)]
struct AppState {
    data: Arc<RwLock<AppData>>,
    storage: Arc<Storage>,
    sessions: Arc<RwLock<HashMap<String, SessionState>>>,
    login_attempts: Arc<RwLock<HashMap<String, LoginAttemptState>>>,
    dashboard_tree_states: Arc<RwLock<HashMap<String, String>>>,
    dashboard_tree_state_path: Arc<PathBuf>,
    network_settings: Arc<RwLock<NetworkSettings>>,
    config: AppConfig,
}

#[derive(Clone)]
struct LoginAttemptState {
    failures: u32,
    blocked_until: Option<DateTime<Utc>>,
}

#[derive(Clone)]
struct LoginWaitState {
    blocked_until_epoch_ms: i64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ProfileAccess {
    Full,
    Limited,
}

#[derive(Clone, Copy)]
struct DocumentViewPolicy {
    branch_requires_password: bool,
    can_view_branch: bool,
    can_view_unit: bool,
}

#[derive(Clone)]
struct MemberSection {
    unit: Organization,
    members: Vec<Member>,
}

#[derive(Deserialize, Default, Clone)]
struct DocumentQuery {
    doc: Option<String>,
    panel: Option<String>,
}

#[derive(Deserialize)]
struct DocumentUpdateForm {
    csrf: String,
    preview_text: String,
}

#[derive(Deserialize)]
struct DocumentMenuActionForm {
    csrf: String,
    action: String,
    value: Option<String>,
}

#[derive(Deserialize)]
struct SharedDocumentSyncForm {
    csrf: String,
    methods_json: Option<String>,
}

#[derive(Deserialize)]
struct ProfileDocumentPushUpForm {
    csrf: String,
    preview_text: String,
}

#[derive(Deserialize)]
struct TreeUserCredentialForm {
    csrf: String,
    username: String,
    password: String,
}

#[derive(Serialize)]
struct TreeUserCredentialResponse {
    username: String,
    message: String,
}

#[derive(Deserialize)]
struct DashboardTreeStateForm {
    csrf: String,
    snapshot: String,
}

#[derive(Serialize)]
struct DashboardReportUnitRecord {
    id: String,
    name: String,
    tier: u32,
    member_count: usize,
    new_member_count: usize,
    age_buckets: Vec<DashboardReportBucket>,
    education_buckets: Vec<DashboardReportBucket>,
    completion_buckets: Vec<DashboardReportBucket>,
    rank_buckets: Vec<DashboardReportBucket>,
    activities: Vec<String>,
}

#[derive(Serialize)]
struct DashboardReportBucket {
    label: String,
    value: usize,
}

struct UploadedReportMemberRow {
    birth_date: String,
    education: String,
    rank: String,
    completion: String,
    activity: String,
}

#[derive(Deserialize, Default)]
struct SyncQuery {
    since: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, Default)]
struct SyncSnapshot {
    organizations: Vec<Organization>,
    members: Vec<Member>,
    activities: Vec<Activity>,
    documents: Vec<Document>,
}

#[derive(Serialize, Deserialize)]
struct SyncPayload {
    full_sync: bool,
    generated_at: String,
    latest_update_at: String,
    snapshot: SyncSnapshot,
}

pub async fn run() -> anyhow::Result<()> {
    let runtime_dir =
        PathBuf::from(std::env::var("APP_RUNTIME_DIR").unwrap_or_else(|_| "runtime".to_owned()));
    let skip_demo_seed = matches!(
        std::env::var("APP_SKIP_DEMO_SEED")
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes" | "on"
    );
    let _log_guard = setup_logging(&runtime_dir)?;
    let data_dir = runtime_dir.join("data");
    let key_dir = runtime_dir.join("keys");
    let dashboard_tree_state_path = data_dir.join("dashboard_tree_states.json");
    let master_key = MasterKey::load_or_create(&key_dir.join("master_key.b64"))?;
    let (kem_public_key, _kem_private_key) = load_or_create_kem_pair(&key_dir, &master_key)?;
    let storage = Arc::new(Storage::new(&data_dir, master_key)?);
    info!(data_dir = %data_dir.display(), key_dir = %key_dir.display(), "loading persisted application data");
    let mut data = storage.load()?;
    let mut startup_state_changed = false;

    let normalized_members = normalize_members(&mut data);
    if normalized_members > 0 {
        startup_state_changed = true;
        info!(
            updated_members = normalized_members,
            "normalized legacy member records for the spreadsheet view"
        );
    }

    let users_before = data.users.clone();
    ensure_bootstrap_admin(&mut data)?;
    if data.users != users_before {
        startup_state_changed = true;
    }

    let had_organizations = !data.organizations.is_empty();
    if skip_demo_seed {
        info!("skipping demo tree and demo documents for this startup");
    } else {
        ensure_demo_tree(&mut data)?;
        if !had_organizations && !data.organizations.is_empty() {
            startup_state_changed = true;
        }
    }

    let dropped_b = drop_b_tier_nodes(&mut data);
    if dropped_b > 0 {
        startup_state_changed = true;
        info!(
            dropped = dropped_b,
            "removed tier-4 (b-level) nodes from the demo tree"
        );
    }

    let renamed = normalize_org_node_credentials(&mut data)?;
    if renamed > 0 {
        startup_state_changed = true;
        info!(
            renamed_users = renamed,
            "renamed org node users to match node labels"
        );
    }
    if !skip_demo_seed {
        let documents_before_cleanup = data.documents.len();
        ensure_demo_documents(&mut data, storage.docs_dir(), &kem_public_key)?;
        if data.documents.len() != documents_before_cleanup {
            startup_state_changed = true;
        }
    }
    if startup_state_changed {
        storage.save(&data)?;
    }
    info!(
        organizations = data.organizations.len(),
        users = data.users.len(),
        members = data.members.len(),
        activities = data.activities.len(),
        documents = data.documents.len(),
        "application state ready"
    );

    let network_mode = NetworkMode::from_env();
    let state = AppState {
        data: Arc::new(RwLock::new(data)),
        storage,
        sessions: Arc::new(RwLock::new(HashMap::new())),
        login_attempts: Arc::new(RwLock::new(HashMap::new())),
        dashboard_tree_states: Arc::new(RwLock::new(load_dashboard_tree_states(
            &dashboard_tree_state_path,
        ))),
        dashboard_tree_state_path: Arc::new(dashboard_tree_state_path),
        network_settings: Arc::new(RwLock::new(NetworkSettings {
            mode: network_mode,
            ip_whitelist: vec![],
        })),
        config: AppConfig {
            bind_addr: std::env::var("APP_BIND_ADDR")
                .unwrap_or_else(|_| "127.0.0.1:8080".to_owned()),
            tree_admin_key: load_or_create_tree_admin_key(&key_dir)?,
            kem_public_key: kem_public_key.to_owned(),
            require_https: matches!(
                std::env::var("APP_REQUIRE_HTTPS")
                    .unwrap_or_default()
                    .trim()
                    .to_ascii_lowercase()
                    .as_str(),
                "1" | "true" | "yes" | "on"
            ),
        },
    };
    {
        let storage = state.storage.clone();
        let data = state.data.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                let should_flush = match storage.cache_due() {
                    Ok(value) => value,
                    Err(_) => continue,
                };
                if !should_flush {
                    continue;
                }
                let snapshot = data.read().await.clone();
                let _ = storage.flush_cache_to_main(&snapshot);
            }
        });
    }
    let app = build_router(state.clone());

    let addr: SocketAddr = state
        .config
        .bind_addr
        .parse()
        .with_context(|| format!("invalid bind address: {}", state.config.bind_addr))?;
    info!(
        transport = if state.config.require_https {
            "https-required"
        } else {
            "http-or-https"
        },
        "starting service on http://{} in {} mode",
        addr,
        network_mode.as_str()
    );
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => listener,
        Err(bind_error) => {
            error!(%bind_error, addr = %addr, "failed to bind listener");
            return Err(bind_error.into());
        }
    };
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

fn setup_logging(runtime_dir: &StdPath) -> anyhow::Result<WorkerGuard> {
    let log_dir = runtime_dir.join("logs");
    fs::create_dir_all(&log_dir)
        .with_context(|| format!("failed to create log directory: {}", log_dir.display()))?;

    let file_path = log_dir.join("app.log");
    let file_appender = tracing_appender::rolling::never(&log_dir, "app.log");
    let (file_writer, guard) = tracing_appender::non_blocking(file_appender);

    tracing_subscriber::registry()
        .with(fmt::layer().compact())
        .with(
            fmt::layer()
                .compact()
                .with_ansi(false)
                .with_writer(file_writer),
        )
        .try_init()
        .context("failed to initialize logging")?;

    info!(log_file = %file_path.display(), "file logging enabled");
    Ok(guard)
}

fn build_router(state: AppState) -> Router {
    let assets = static_assets();
    Router::new()
        .route("/", get(index))
        .route("/health", get(health))
        .route("/service-worker.js", get(service_worker_asset))
        .route("/assets/emblem.svg", get(serve_emblem_svg))
        .route("/assets/site-bg.png", get(serve_site_background))
        .route("/favicon.ico", get(serve_emblem_svg))
        .route("/favicon.svg", get(serve_emblem_svg))
        .route(
            &format!("/assets/{}", assets.base_css_filename),
            get(serve_base_css),
        )
        .route(
            &format!("/assets/{}", assets.dashboard_js_filename),
            get(serve_dashboard_js),
        )
        .route(
            &format!("/assets/{}", assets.profile_js_filename),
            get(serve_profile_js),
        )
        .route(
            &format!("/assets/{}", assets.sync_js_filename),
            get(serve_sync_js),
        )
        .route(
            &format!("/assets/{}", assets.login_js_filename),
            get(serve_login_js),
        )
        .route("/settings/network", post(update_network_settings))
        .route("/settings/password", post(update_password_settings))
        .route("/sync/bootstrap", get(sync_bootstrap))
        .route("/documents/manage", get(document_manager))
        .route("/units/{id}", get(unit_profile))
        .route("/units/{id}/documents/unlock", post(unlock_unit_documents))
        .route(
            "/units/{unit_id}/documents/{doc_id}",
            post(update_unit_document_preview),
        )
        .route(
            "/units/{unit_id}/documents/{doc_id}/menu-action",
            post(apply_profile_document_menu_action),
        )
        .route(
            "/units/{unit_id}/documents/{doc_id}/push-up",
            post(push_profile_document_up),
        )
        .route(
            "/units/{id}/documents/sync-shared",
            post(sync_shared_documents),
        )
        .route(
            "/dashboard/tree-users/{org_id}",
            post(update_dashboard_tree_user_credentials),
        )
        .route("/dashboard/tree-state", post(update_dashboard_tree_state))
        .route("/units/{id}/members/download", post(download_members_csv))
        .route("/units/{unit_id}/members/{member_id}", post(update_member))
        .route("/login", post(login))
        .route("/logout", post(logout))
        .route("/orgs", post(create_root_org))
        .route("/orgs/{id}/children", post(create_child_org))
        .route("/orgs/{id}/members", post(add_member))
        .route("/orgs/{id}/activities", post(add_activity))
        .route("/activities/{id}/review", post(review_activity))
        .route("/users", post(create_user))
        .route("/documents", post(upload_document))
        .route("/documents/{id}/download", post(download_document))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            security_middleware,
        ))
        .layer(CompressionLayer::new().gzip(true))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Static asset bundle (CSS / JS) with content-hashed URLs.
// Each asset body is built once at startup and served with
// `Cache-Control: public, max-age=31536000, immutable` so the browser caches
// it forever. Pages reference the hashed URL via `static_assets()`.
// ---------------------------------------------------------------------------

pub(crate) struct StaticAssets {
    pub base_css_url: String,
    pub dashboard_js_url: String,
    pub profile_js_url: String,
    pub sync_js_url: String,
    pub login_js_url: String,
    base_css_filename: String,
    dashboard_js_filename: String,
    profile_js_filename: String,
    sync_js_filename: String,
    login_js_filename: String,
}

fn short_hash(body: &str) -> String {
    let digest = Sha256::digest(body.as_bytes());
    let mut out = String::with_capacity(16);
    for byte in &digest[..8] {
        use std::fmt::Write as _;
        let _ = write!(out, "{:02x}", byte);
    }
    out
}

pub(crate) fn static_assets() -> &'static StaticAssets {
    static CACHE: OnceLock<StaticAssets> = OnceLock::new();
    CACHE.get_or_init(|| {
        let base_css = base_styles();
        let dashboard_js = dashboard_script();
        let profile_js = profile_script();
        let sync_js = sync_client_script();
        let login_js = login_script();
        let base_css_filename = format!("base.{}.css", short_hash(base_css));
        let dashboard_js_filename = format!("dashboard.{}.js", short_hash(dashboard_js));
        let profile_js_filename = format!("profile.{}.js", short_hash(profile_js));
        let sync_js_filename = format!("sync.{}.js", short_hash(sync_js));
        let login_js_filename = format!("login.{}.js", short_hash(login_js));
        StaticAssets {
            base_css_url: format!("/assets/{}", base_css_filename),
            dashboard_js_url: format!("/assets/{}", dashboard_js_filename),
            profile_js_url: format!("/assets/{}", profile_js_filename),
            sync_js_url: format!("/assets/{}", sync_js_filename),
            login_js_url: format!("/assets/{}", login_js_filename),
            base_css_filename,
            dashboard_js_filename,
            profile_js_filename,
            sync_js_filename,
            login_js_filename,
        }
    })
}

async fn serve_emblem_svg() -> Response {
    // Ưu tiên logo PNG thật nếu người dùng đặt file vào <runtime>/branding/logo.png
    // (vd thả vào volume Docker /data/branding/logo.png) -> không cần build lại.
    let runtime_dir = std::env::var("APP_RUNTIME_DIR").unwrap_or_else(|_| "runtime".to_owned());
    let logo_path = std::path::Path::new(&runtime_dir)
        .join("branding")
        .join("logo.png");
    if let Ok(bytes) = std::fs::read(&logo_path) {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("image/png"),
        );
        // Cache ngắn để khi thay logo sẽ cập nhật sớm.
        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=300"),
        );
        return (StatusCode::OK, headers, bytes).into_response();
    }
    // Mặc định: logo.png chính thức nhúng sẵn trong binary.
    static LOGO_PNG: &[u8] = include_bytes!("../logo.png");
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("image/png"));
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=86400"),
    );
    (StatusCode::OK, headers, LOGO_PNG).into_response()
}

/// Phục vụ ảnh nền. Ưu tiên file thả vào volume <runtime>/branding/background.png,
/// nếu không có thì dùng AnhNen.png nhúng sẵn trong binary.
async fn serve_site_background() -> Response {
    let runtime_dir = std::env::var("APP_RUNTIME_DIR").unwrap_or_else(|_| "runtime".to_owned());
    let bg_path = std::path::Path::new(&runtime_dir)
        .join("branding")
        .join("background.png");
    if let Ok(bytes) = std::fs::read(&bg_path) {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("image/png"));
        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=300"),
        );
        return (StatusCode::OK, headers, bytes).into_response();
    }
    static BG_PNG: &[u8] = include_bytes!("../AnhNen.png");
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("image/png"));
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=86400"),
    );
    (StatusCode::OK, headers, BG_PNG).into_response()
}

fn cached_asset_response(content_type: &'static str, body: &'static str) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=31536000, immutable"),
    );
    (StatusCode::OK, headers, body).into_response()
}

async fn serve_base_css() -> Response {
    cached_asset_response("text/css; charset=utf-8", base_styles())
}
async fn serve_dashboard_js() -> Response {
    cached_asset_response("application/javascript; charset=utf-8", dashboard_script())
}
async fn serve_profile_js() -> Response {
    cached_asset_response("application/javascript; charset=utf-8", profile_script())
}
async fn serve_sync_js() -> Response {
    cached_asset_response(
        "application/javascript; charset=utf-8",
        sync_client_script(),
    )
}
async fn serve_login_js() -> Response {
    cached_asset_response("application/javascript; charset=utf-8", login_script())
}

async fn security_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    if state.config.require_https && !request_uses_https(&request) {
        return (
            StatusCode::UPGRADE_REQUIRED,
            Html("<h1>426</h1><p>Yeu cau ket noi HTTPS.</p>".to_owned()),
        )
            .into_response();
    }

    let network_settings = state.network_settings.read().await.clone();
    if network_settings.mode == NetworkMode::LanOnly {
        let Some(connect_info) = request.extensions().get::<ConnectInfo<SocketAddr>>() else {
            return forbidden_network_response();
        };
        if !is_allowed_lan_ip(connect_info.0.ip(), &network_settings.ip_whitelist) {
            return forbidden_network_response();
        }
    }

    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    // Only force `no-store` on dynamic responses. Static assets set their own
    // `Cache-Control: public, max-age=31536000, immutable` and we must not
    // overwrite that or we'd kill browser caching of CSS/JS.
    if !headers.contains_key(header::CACHE_CONTROL) {
        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store, no-cache, must-revalidate"),
        );
    }
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; worker-src 'self' blob:; object-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'"),
    );
    if state.config.require_https {
        headers.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        );
    }
    response
}

fn request_uses_https(request: &Request) -> bool {
    if request.uri().scheme_str() == Some("https") {
        return true;
    }
    if request
        .headers()
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.eq_ignore_ascii_case("https"))
        .unwrap_or(false)
    {
        return true;
    }
    request
        .headers()
        .get("forwarded")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_ascii_lowercase().contains("proto=https"))
        .unwrap_or(false)
}

async fn health(State(state): State<AppState>) -> Response {
    let network_settings = state.network_settings.read().await.clone();
    let body = format!(
        "status=ok\nmode={}\ntime={}\n",
        network_settings.mode.as_str(),
        now_string()
    );
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        body,
    )
        .into_response()
}

async fn update_network_settings(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<NetworkSettingsForm>,
) -> Response {
    let Some((user, session)) = require_session(&state, &jar).await else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if validate_csrf(&session, &form.csrf).is_err() || user.role != UserRole::RootAdmin {
        return StatusCode::FORBIDDEN.into_response();
    }

    let Some(mode) = NetworkMode::from_control_value(&form.mode) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(NetworkSettingsResponse {
                mode: String::new(),
                is_lan: false,
                ip_whitelist: Vec::new(),
                message: String::from("Chế độ mạng không hợp lệ."),
            }),
        )
            .into_response();
    };

    let Ok(ip_whitelist) = parse_ip_whitelist(&form.ip_whitelist) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(NetworkSettingsResponse {
                mode: mode.as_str().to_owned(),
                is_lan: mode == NetworkMode::LanOnly,
                ip_whitelist: Vec::new(),
                message: String::from("Danh sách IP không hợp lệ."),
            }),
        )
            .into_response();
    };

    let mut settings = state.network_settings.write().await;
    settings.mode = mode;
    settings.ip_whitelist = ip_whitelist;
    let response = NetworkSettingsResponse {
        mode: settings.mode.as_str().to_owned(),
        is_lan: settings.mode == NetworkMode::LanOnly,
        ip_whitelist: settings
            .ip_whitelist
            .iter()
            .map(ToString::to_string)
            .collect(),
        message: String::from("Đã cập nhật chế độ mạng."),
    };
    (StatusCode::OK, Json(response)).into_response()
}

async fn update_password_settings(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<PasswordSettingsForm>,
) -> Response {
    let Some((user, session)) = require_session(&state, &jar).await else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(PasswordSettingsResponse {
                ok: false,
                message: String::from("Phiên đăng nhập đã hết hạn."),
            }),
        )
            .into_response();
    };

    if validate_csrf(&session, &form.csrf).is_err() {
        return (
            StatusCode::FORBIDDEN,
            Json(PasswordSettingsResponse {
                ok: false,
                message: String::from("Yêu cầu không hợp lệ, vui lòng tải lại trang."),
            }),
        )
            .into_response();
    }

    let current_password = form.current_password.trim();
    let new_password = form.new_password.trim();
    let confirm_password = form.confirm_password.trim();

    if current_password.is_empty() || new_password.is_empty() || confirm_password.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(PasswordSettingsResponse {
                ok: false,
                message: String::from("Cần nhập đủ mật khẩu hiện tại, mật khẩu mới và xác nhận."),
            }),
        )
            .into_response();
    }

    if !verify_password(&user.password_hash, current_password) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(PasswordSettingsResponse {
                ok: false,
                message: String::from("Mật khẩu hiện tại không đúng."),
            }),
        )
            .into_response();
    }

    if new_password != confirm_password {
        return (
            StatusCode::BAD_REQUEST,
            Json(PasswordSettingsResponse {
                ok: false,
                message: String::from("Mật khẩu xác nhận chưa khớp."),
            }),
        )
            .into_response();
    }

    let password_hash = match hash_password(new_password) {
        Ok(hash) => hash,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(PasswordSettingsResponse {
                    ok: false,
                    message: String::from("Không mã hóa được mật khẩu mới."),
                }),
            )
                .into_response();
        }
    };

    let mut data = state.data.write().await;
    let Some(target_user) = data.users.iter_mut().find(|item| item.id == user.id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(PasswordSettingsResponse {
                ok: false,
                message: String::from("Không tìm thấy tài khoản để cập nhật."),
            }),
        )
            .into_response();
    };
    target_user.password_hash = password_hash;

    if persist(&state, &data).is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(PasswordSettingsResponse {
                ok: false,
                message: String::from("Không lưu được mật khẩu mới."),
            }),
        )
            .into_response();
    }

    (
        StatusCode::OK,
        Json(PasswordSettingsResponse {
            ok: true,
            message: String::from("Đã đổi mật khẩu tài khoản."),
        }),
    )
        .into_response()
}

async fn service_worker_asset() -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/javascript; charset=utf-8"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        HeaderName::from_static("service-worker-allowed"),
        HeaderValue::from_static("/"),
    );
    (StatusCode::OK, headers, service_worker_script()).into_response()
}

fn load_or_create_tree_admin_key(key_dir: &StdPath) -> anyhow::Result<String> {
    if let Ok(env_key) = std::env::var("APP_TREE_KEY") {
        let trimmed = env_key.trim().to_owned();
        if !trimmed.is_empty() {
            return Ok(trimmed);
        }
    }
    let path = key_dir.join("tree_admin_key.txt");
    if path.exists() {
        let raw = fs::read_to_string(&path).context("failed to read tree admin key")?;
        let trimmed = raw.trim().to_owned();
        if !trimmed.is_empty() {
            return Ok(trimmed);
        }
    }
    fs::create_dir_all(key_dir).context("failed to create key directory")?;
    let generated = random_token(24);
    fs::write(&path, &generated).context("failed to persist tree admin key")?;
    info!(
        path = %path.display(),
        "generated new tree admin key (saved to file; use it as APP_TREE_KEY value)"
    );
    Ok(generated)
}

fn ensure_bootstrap_admin(data: &mut AppData) -> anyhow::Result<()> {
    let bootstrap_username =
        std::env::var("APP_BOOTSTRAP_USERNAME").unwrap_or_else(|_| "Admin@1999".to_owned());
    let bootstrap_password =
        std::env::var("APP_BOOTSTRAP_PASSWORD").unwrap_or_else(|_| "Admin@1999".to_owned());

    // Migrate legacy weak admin (username=="admin") to the new strong default.
    if let Some(legacy) = data
        .users
        .iter_mut()
        .find(|u| u.role == UserRole::RootAdmin && u.username == "admin")
    {
        legacy.username = bootstrap_username.clone();
        legacy.password_hash = hash_password(&bootstrap_password)?;
        info!(username = %bootstrap_username, "migrated legacy admin/admin account to new credentials");
        return Ok(());
    }

    if !data.users.is_empty() {
        return Ok(());
    }

    data.users.push(User {
        id: new_id("user"),
        username: bootstrap_username.clone(),
        password_hash: hash_password(&bootstrap_password)?,
        role: UserRole::RootAdmin,
        org_id: None,
        tree_key_enabled: true,
        active: true,
        created_at: now_string(),
    });
    info!(username = %bootstrap_username, "created bootstrap admin account");
    Ok(())
}

fn load_dashboard_tree_states(path: &StdPath) -> HashMap<String, String> {
    fs::read_to_string(path)
        .ok()
        .and_then(|raw| serde_json::from_str::<HashMap<String, String>>(&raw).ok())
        .unwrap_or_default()
}

fn save_dashboard_tree_states(
    path: &StdPath,
    states: &HashMap<String, String>,
) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context("failed to create dashboard tree state directory")?;
    }
    let encoded =
        serde_json::to_vec_pretty(states).context("failed to encode dashboard tree states")?;
    fs::write(path, encoded).context("failed to write dashboard tree states")
}

fn dashboard_tree_state_key(user: &User) -> String {
    user.org_id
        .as_ref()
        .map(|org_id| format!("org:{org_id}"))
        .unwrap_or_else(|| String::from("root"))
}

fn json_for_inline_script(value: &str) -> String {
    serde_json::to_string(value)
        .unwrap_or_else(|_| String::from("\"\""))
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
}

fn json_value_for_inline_script<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value)
        .unwrap_or_else(|_| String::from("[]"))
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
}

fn parse_date_year(value: &str) -> Option<i32> {
    value.get(0..4)?.parse::<i32>().ok()
}

fn member_age(member: &Member) -> Option<i32> {
    let birth_year = parse_date_year(&member.birth_date)?;
    Some(Utc::now().year() - birth_year)
}

fn bucket_vec(labels: &[&str], counts: &HashMap<String, usize>) -> Vec<DashboardReportBucket> {
    labels
        .iter()
        .map(|label| DashboardReportBucket {
            label: (*label).to_owned(),
            value: *counts.get(*label).unwrap_or(&0),
        })
        .collect()
}

fn education_bucket(member: &Member) -> &'static str {
    match member.year.rem_euclid(4) {
        0 => "Đại học",
        1 => "Sau đại học",
        2 => "Cao đẳng",
        _ => "Trung cấp",
    }
}

fn rank_bucket(member: &Member) -> &'static str {
    match member.title.as_str() {
        "Bí thư" => "Bí thư",
        "Phó bí thư" => "Phó bí thư",
        "Chủ tịch" => "Chủ tịch",
        _ => "Ủy viên",
    }
}

fn normalize_report_header(value: &str) -> String {
    value
        .trim()
        .to_lowercase()
        .replace("đ", "d")
        .replace(' ', "")
}

fn normalize_report_value(value: &str) -> String {
    normalize_report_header(value).replace('-', "")
}

fn canonical_report_bucket(value: &str, allowed: &[&str]) -> String {
    let key = normalize_report_value(value);
    allowed
        .iter()
        .find(|label| normalize_report_value(label) == key)
        .map(|label| (*label).to_owned())
        .unwrap_or_else(|| value.trim().to_owned())
}

fn report_rows_from_preview(preview: &str) -> Vec<UploadedReportMemberRow> {
    let rows = parse_preview_rows(preview);
    let Some(header) = rows.first() else {
        return Vec::new();
    };
    let mut columns = HashMap::new();
    for (index, cell) in header.iter().enumerate() {
        columns.insert(normalize_report_header(cell), index);
    }
    let full_name_key = normalize_report_header("Họ tên");
    let full_name_alt_key = normalize_report_header("Họ và tên");
    let birth_date_key = normalize_report_header("Sinh ngày");
    let education_key = normalize_report_header("Trình độ");
    let rank_key = normalize_report_header("Cấp bậc");
    let completion_key = normalize_report_header("Mức độ hoàn thành nhiệm vụ");
    let activity_key = normalize_report_header("Hoạt động của đơn vị");
    let has_full_name =
        columns.contains_key(&full_name_key) || columns.contains_key(&full_name_alt_key);
    let required = [
        &birth_date_key,
        &education_key,
        &rank_key,
        &completion_key,
        &activity_key,
    ];
    if !has_full_name || required.iter().any(|key| !columns.contains_key(*key)) {
        return Vec::new();
    }
    let cell_at = |row: &[String], key: &str| -> String {
        columns
            .get(key)
            .and_then(|index| row.get(*index))
            .map(|value| value.trim().to_owned())
            .unwrap_or_default()
    };
    rows.into_iter()
        .skip(1)
        .filter(|row| row.iter().any(|cell| !cell.trim().is_empty()))
        .map(|row| UploadedReportMemberRow {
            birth_date: cell_at(&row, &birth_date_key),
            education: cell_at(&row, &education_key),
            rank: cell_at(&row, &rank_key),
            completion: cell_at(&row, &completion_key),
            activity: cell_at(&row, &activity_key),
        })
        .collect()
}

fn report_rows_from_documents(org: &Organization, data: &AppData) -> Vec<UploadedReportMemberRow> {
    let mut scope_ids = descendant_ids(&data.organizations, &org.id);
    scope_ids.insert(org.id.clone());
    let mut latest_by_org: HashMap<String, (String, Vec<UploadedReportMemberRow>)> = HashMap::new();
    for document in data
        .documents
        .iter()
        .filter(|document| scope_ids.contains(&document.org_id) && !is_shared_document(document))
    {
        let rows = report_rows_from_preview(&document.preview_text);
        if rows.is_empty() {
            continue;
        }
        let should_replace = latest_by_org
            .get(&document.org_id)
            .map(|(uploaded_at, _)| document.uploaded_at > *uploaded_at)
            .unwrap_or(true);
        if should_replace {
            latest_by_org.insert(
                document.org_id.clone(),
                (document.uploaded_at.clone(), rows),
            );
        }
    }
    let mut grouped_rows = latest_by_org.into_values().collect::<Vec<_>>();
    grouped_rows.sort_by(|left, right| left.0.cmp(&right.0));
    grouped_rows
        .into_iter()
        .flat_map(|(_, rows)| rows)
        .collect()
}

fn parse_report_birth_year(value: &str) -> Option<i32> {
    for token in value.split(|ch: char| !ch.is_ascii_digit()) {
        if token.len() == 4
            && let Ok(year) = token.parse::<i32>()
            && (1930..=Utc::now().year()).contains(&year)
        {
            return Some(year);
        }
    }
    None
}

fn split_report_activities(value: &str) -> Vec<String> {
    let mut activities = Vec::new();
    for line in value.lines().map(str::trim).filter(|line| !line.is_empty()) {
        let starts_new_activity = line
            .chars()
            .find(|ch| ch.is_alphabetic())
            .map(|ch| ch.is_uppercase())
            .unwrap_or(false);
        if starts_new_activity || activities.is_empty() {
            activities.push(line.to_owned());
        } else if let Some(last) = activities.last_mut() {
            last.push(' ');
            last.push_str(line);
        }
    }
    activities
}

fn build_uploaded_report_record(
    org: &Organization,
    rows: Vec<UploadedReportMemberRow>,
) -> DashboardReportUnitRecord {
    let current_year = Utc::now().year();
    let mut age_counts: HashMap<String, usize> = HashMap::new();
    let mut education_counts: HashMap<String, usize> = HashMap::new();
    let mut rank_counts: HashMap<String, usize> = HashMap::new();
    let mut completion_counts: HashMap<String, usize> = HashMap::new();
    let mut seen_activities = HashSet::new();
    let mut activities = Vec::new();

    for row in &rows {
        let age_label =
            match parse_report_birth_year(&row.birth_date).map(|year| current_year - year) {
                Some(age) if age < 30 => "Dưới 30",
                Some(age) if age < 40 => "30-39",
                Some(age) if age < 50 => "40-49",
                Some(age) if age < 60 => "50-59",
                _ => "60+",
            };
        *age_counts.entry(age_label.to_owned()).or_default() += 1;
        *education_counts
            .entry(canonical_report_bucket(
                &row.education,
                &["THPT", "Đại học", "Thạc sĩ", "Tiến sĩ"],
            ))
            .or_default() += 1;
        *rank_counts
            .entry(canonical_report_bucket(
                &row.rank,
                &["Cấp tá", "Cấp úy", "Hạ sỹ quan", "Dân sự"],
            ))
            .or_default() += 1;
        *completion_counts
            .entry(canonical_report_bucket(
                &row.completion,
                &["Xuất sắc", "Tốt", "Hoàn thành", "Không hoàn thành"],
            ))
            .or_default() += 1;
        for activity in split_report_activities(&row.activity) {
            if seen_activities.insert(activity.clone()) {
                activities.push(activity);
            }
        }
    }

    DashboardReportUnitRecord {
        id: org.id.clone(),
        name: org.name.clone(),
        tier: org.tier,
        member_count: rows.len(),
        new_member_count: 0,
        age_buckets: bucket_vec(&["Dưới 30", "30-39", "40-49", "50-59", "60+"], &age_counts),
        education_buckets: bucket_vec(
            &["THPT", "Đại học", "Thạc sĩ", "Tiến sĩ"],
            &education_counts,
        ),
        completion_buckets: bucket_vec(
            &["Xuất sắc", "Tốt", "Hoàn thành", "Không hoàn thành"],
            &completion_counts,
        ),
        rank_buckets: bucket_vec(&["Cấp tá", "Cấp úy", "Hạ sỹ quan", "Dân sự"], &rank_counts),
        activities,
    }
}

fn build_dashboard_report_record(org: &Organization, data: &AppData) -> DashboardReportUnitRecord {
    let uploaded_rows = report_rows_from_documents(org, data);
    if !uploaded_rows.is_empty() {
        return build_uploaded_report_record(org, uploaded_rows);
    }

    let mut scope_ids = descendant_ids(&data.organizations, &org.id);
    scope_ids.insert(org.id.clone());
    let current_year = Utc::now().year();
    let members: Vec<&Member> = data
        .members
        .iter()
        .filter(|member| scope_ids.contains(&member.org_id) && member.active)
        .collect();
    let activities: Vec<&Activity> = data
        .activities
        .iter()
        .filter(|activity| scope_ids.contains(&activity.org_id))
        .collect();

    let mut age_counts: HashMap<String, usize> = HashMap::new();
    let mut education_counts: HashMap<String, usize> = HashMap::new();
    let mut rank_counts: HashMap<String, usize> = HashMap::new();
    for member in &members {
        let age_label = match member_age(member) {
            Some(age) if age < 30 => "Dưới 30",
            Some(age) if age < 40 => "30-39",
            Some(age) if age < 50 => "40-49",
            Some(age) if age < 60 => "50-59",
            _ => "60+",
        };
        *age_counts.entry(age_label.to_owned()).or_default() += 1;
        *education_counts
            .entry(education_bucket(member).to_owned())
            .or_default() += 1;
        *rank_counts
            .entry(rank_bucket(member).to_owned())
            .or_default() += 1;
    }

    let mut completion_counts: HashMap<String, usize> = HashMap::new();
    for activity in &activities {
        let label = match activity.status {
            ActivityStatus::Completed => "Hoàn thành",
            ActivityStatus::Ongoing => "Đang thực hiện",
            ActivityStatus::Planned => "Kế hoạch",
        };
        *completion_counts.entry(label.to_owned()).or_default() += 1;
    }

    let mut activity_titles: Vec<String> = activities
        .iter()
        .map(|activity| format!("{} - {}", activity.year, activity.title))
        .collect();
    activity_titles.sort();

    DashboardReportUnitRecord {
        id: org.id.clone(),
        name: org.name.clone(),
        tier: org.tier,
        member_count: members.len(),
        new_member_count: members
            .iter()
            .filter(|member| parse_date_year(&member.joined_at) == Some(current_year))
            .count(),
        age_buckets: bucket_vec(&["Dưới 30", "30-39", "40-49", "50-59", "60+"], &age_counts),
        education_buckets: bucket_vec(
            &["Sau đại học", "Đại học", "Cao đẳng", "Trung cấp"],
            &education_counts,
        ),
        completion_buckets: bucket_vec(
            &["Hoàn thành", "Đang thực hiện", "Kế hoạch"],
            &completion_counts,
        ),
        rank_buckets: bucket_vec(
            &["Bí thư", "Phó bí thư", "Chủ tịch", "Ủy viên"],
            &rank_counts,
        ),
        activities: activity_titles,
    }
}

fn drop_b_tier_nodes(data: &mut AppData) -> usize {
    let b_ids: Vec<String> = data
        .organizations
        .iter()
        .filter(|org| org.tier >= 4)
        .map(|org| org.id.clone())
        .collect();
    if b_ids.is_empty() {
        return 0;
    }
    let b_set: std::collections::HashSet<&str> = b_ids.iter().map(|s| s.as_str()).collect();
    data.organizations
        .retain(|org| !b_set.contains(org.id.as_str()));
    data.users.retain(|u| {
        u.org_id
            .as_deref()
            .map(|id| !b_set.contains(id))
            .unwrap_or(true)
    });
    data.members.retain(|m| !b_set.contains(m.org_id.as_str()));
    data.activities
        .retain(|a| !b_set.contains(a.org_id.as_str()));
    b_ids.len()
}

fn ensure_demo_tree(data: &mut AppData) -> anyhow::Result<()> {
    if !data.organizations.is_empty() {
        info!(
            organizations = data.organizations.len(),
            "demo tree already present, skipping seed"
        );
        return Ok(());
    }

    info!("seeding demo organization tree and sample data");
    let mut counters = HashMap::from([('e', 0_u32), ('d', 0_u32), ('c', 0_u32), ('b', 0_u32)]);

    let root = make_seed_org(None, 0, "f", "Đơn vị gốc F");
    data.organizations.push(root.clone());
    add_seed_user(data, &root, UserRole::OrgManager, true)?;
    add_seed_members(data, &root);
    add_seed_activities(data, &root);

    for _ in 0..3 {
        let level1 = next_seed_org(&root.id, 1, 'e', &mut counters, "Nhánh cấp 1");
        data.organizations.push(level1.clone());
        add_seed_user(data, &level1, UserRole::OrgManager, true)?;
        add_seed_members(data, &level1);
        add_seed_activities(data, &level1);

        for _ in 0..4 {
            let level2 = next_seed_org(&level1.id, 2, 'd', &mut counters, "Nhánh cấp 2");
            data.organizations.push(level2.clone());
            add_seed_user(data, &level2, UserRole::OrgManager, true)?;
            add_seed_members(data, &level2);
            add_seed_activities(data, &level2);

            for _ in 0..3 {
                let level3 = next_seed_org(&level2.id, 3, 'c', &mut counters, "Nhánh cấp 3");
                data.organizations.push(level3.clone());
                add_seed_user(data, &level3, UserRole::OrgManager, false)?;
                add_seed_members(data, &level3);
                add_seed_activities(data, &level3);
            }
        }
    }

    info!(
        organizations = data.organizations.len(),
        users = data.users.len(),
        members = data.members.len(),
        activities = data.activities.len(),
        "demo seed completed"
    );
    Ok(())
}

fn ensure_demo_documents(
    data: &mut AppData,
    _docs_dir: &std::path::Path,
    _kem_public_key: &str,
) -> anyhow::Result<()> {
    let mut removed_paths = Vec::new();
    data.documents.retain(|document| {
        let keep = !is_legacy_demo_document(document);
        if !keep {
            removed_paths.push(document.encrypted_path.clone());
        }
        keep
    });
    for path in removed_paths {
        let _ = fs::remove_file(path);
    }
    Ok(())
}

fn make_seed_org(parent_id: Option<&str>, tier: u32, label: &str, category: &str) -> Organization {
    Organization {
        id: new_id("org"),
        parent_id: parent_id.map(str::to_owned),
        name: label.to_owned(),
        tier,
        category: category.to_owned(),
        active: true,
        created_at: now_string(),
        updated_at: now_string(),
    }
}

fn next_seed_org(
    parent_id: &str,
    tier: u32,
    prefix: char,
    counters: &mut HashMap<char, u32>,
    category: &str,
) -> Organization {
    let counter = counters.entry(prefix).or_insert(0);
    *counter += 1;
    make_seed_org(
        Some(parent_id),
        tier,
        &format!("{}{}", prefix, counter),
        category,
    )
}

fn effective_org_user_credentials(data: &AppData, org_id: &str) -> Option<(String, String)> {
    let (default_username, default_password) =
        default_org_user_credentials(&data.organizations, org_id)?;
    let user = data
        .users
        .iter()
        .find(|item| item.org_id.as_deref() == Some(org_id) && item.active);
    Some(match user {
        Some(user) => (
            if user.username.trim().is_empty() {
                default_username
            } else {
                user.username.clone()
            },
            default_password,
        ),
        None => (default_username, default_password),
    })
}

fn add_seed_user(
    data: &mut AppData,
    org: &Organization,
    role: UserRole,
    tree_key_enabled: bool,
) -> anyhow::Result<()> {
    let (username, password) = default_org_user_credentials(&data.organizations, &org.id)
        .unwrap_or_else(|| (org.name.to_lowercase(), org.name.to_lowercase()));
    data.users.push(User {
        id: new_id("user"),
        username,
        password_hash: hash_password(&password)?,
        role,
        org_id: Some(org.id.clone()),
        tree_key_enabled,
        active: true,
        created_at: now_string(),
    });
    Ok(())
}

fn add_seed_members(data: &mut AppData, org: &Organization) {
    let titles = ["Bí thư", "Phó bí thư", "Chủ tịch", "Ủy viên 1", "Ủy viên 2"];
    for (index, title) in titles.into_iter().enumerate() {
        data.members.push(Member {
            id: new_id("member"),
            org_id: org.id.clone(),
            full_name: format!("{} member {}", org.name.to_uppercase(), index + 1),
            title: title.to_owned(),
            year: chrono::Utc::now().year(),
            active: true,
            notes: format!("Hồ sơ mẫu của đơn vị {}", org.name),
            birth_date: seed_birth_date(org.tier, index),
            address: seed_address(org, index),
            phone: seed_phone(org.tier, index),
            joined_at: seed_joined_at(org.tier, index),
            updated_at: now_string(),
        });
    }
}

fn add_seed_activities(data: &mut AppData, org: &Organization) {
    data.activities.push(Activity {
        id: new_id("activity"),
        org_id: org.id.clone(),
        title: format!("Hoạt động trọng tâm {}", org.name),
        year: chrono::Utc::now().year(),
        status: ActivityStatus::Ongoing,
        summary: format!(
            "Theo dõi tiến độ hoạt động thường xuyên của đơn vị {}.",
            org.name
        ),
        reviewed: org.tier <= 1,
        updated_at: now_string(),
    });
}

async fn index(
    State(state): State<AppState>,
    Query(query): Query<DocumentQuery>,
    jar: CookieJar,
) -> Response {
    let current_user = current_user(&state, &jar).await;
    if let Some(user) = current_user.clone() {
        render_dashboard(&state, &user, current_session(&state, &jar).await, &query)
            .await
            .into_response()
    } else {
        Html(render_login(false, None, None).into_string()).into_response()
    }
}

async fn sync_bootstrap(
    State(state): State<AppState>,
    Query(query): Query<SyncQuery>,
    headers: HeaderMap,
    jar: CookieJar,
) -> Response {
    let Some((user, _session)) = require_session(&state, &jar).await else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if validate_sync_request_headers(&headers, state.config.require_https).is_err() {
        return StatusCode::PRECONDITION_FAILED.into_response();
    }
    let Some(sync_key_b64) = header_sync_key(&headers) else {
        return StatusCode::PRECONDITION_FAILED.into_response();
    };

    let since = query.since.as_deref().and_then(parse_rfc3339_utc);
    let data = state.data.read().await;
    let snapshot = build_visible_sync_snapshot(&user, &data, since.as_ref());
    let payload = SyncPayload {
        full_sync: since.is_none(),
        generated_at: now_string(),
        latest_update_at: latest_snapshot_timestamp(&snapshot).unwrap_or_default(),
        snapshot,
    };
    let serialized = match serde_json::to_vec(&payload) {
        Ok(value) => value,
        Err(_) => return internal_error("Không đóng gói được dữ liệu đồng bộ."),
    };
    let envelope = match encrypt_sync_payload(&sync_key_b64, &serialized) {
        Ok(value) => value,
        Err(_) => return internal_error("Không mã hóa được dữ liệu đồng bộ."),
    };
    Json(envelope).into_response()
}

async fn unit_profile(
    State(state): State<AppState>,
    Path(unit_id): Path<String>,
    Query(query): Query<DocumentQuery>,
    jar: CookieJar,
) -> Response {
    let Some((user, session)) = require_session(&state, &jar).await else {
        return Redirect::to("/").into_response();
    };

    let data = state.data.read().await;
    let Some(unit) = data
        .organizations
        .iter()
        .find(|org| org.id == unit_id)
        .cloned()
    else {
        return Redirect::to("/").into_response();
    };
    let Some(access) = profile_access(&user, &unit.id, &data) else {
        return Redirect::to("/").into_response();
    };
    let document_policy = document_view_policy(&user, &unit.id, &data, Some(&session));

    let _member_sections = build_member_sections(&unit, access, &data);
    let branch_source_ids = ancestor_ids(&data.organizations, &unit.id);
    let mut branch_documents: Vec<_> = data
        .organizations
        .iter()
        .filter(|org| branch_source_ids.contains(&org.id))
        .flat_map(|org| effective_shared_documents(&data.organizations, &data.documents, &org.id))
        .collect();
    // Keep "Sổ tổng hợp nhân sự" at top of branch document list
    branch_documents.sort_by_key(|doc| {
        if doc.file_name == "Sổ tổng hợp nhân sự.xlsx" {
            0usize
        } else {
            1
        }
    });
    let mut unit_local_documents: Vec<_> = data
        .documents
        .iter()
        .filter(|item| item.org_id == unit.id && !is_shared_document(item))
        .cloned()
        .collect();
    unit_local_documents.sort_by(|left, right| {
        left.uploaded_at
            .cmp(&right.uploaded_at)
            .then_with(|| left.file_name.cmp(&right.file_name))
    });
    let mut unit_documents =
        effective_shared_documents(&data.organizations, &data.documents, &unit.id);
    unit_documents.extend(unit_local_documents);
    let visible_branch_documents = if document_policy.can_view_branch {
        branch_documents.clone()
    } else {
        Vec::new()
    };
    let mut unified_documents = visible_branch_documents.clone();
    if document_policy.can_view_branch || document_policy.can_view_unit {
        for document in &unit_documents {
            if !unified_documents.iter().any(|item| item.id == document.id) {
                unified_documents.push(document.clone());
            }
        }
    }
    let selected_document = query.doc.as_ref().and_then(|doc_id| {
        unified_documents
            .iter()
            .find(|item| item.id == *doc_id)
            .cloned()
    });
    let report_record = (query.panel.as_deref() == Some("unit-report"))
        .then(|| build_dashboard_report_record(&unit, &data));
    let can_upload_documents_here = can_upload_documents(&data.organizations, &unit.id);
    Html(
        render_unit_profile_page(UnitProfileView {
            user: &user,
            session: &session,
            unit: &unit,
            initial_panel: query.panel.as_deref(),
            access,
            can_upload_documents_here,
            unified_documents: &unified_documents,
            unit_documents: &unit_documents,
            preview_document: selected_document.as_ref(),
            document_policy,
            report_record: report_record.as_ref(),
        })
        .await
        .into_string(),
    )
    .into_response()
}

async fn unlock_unit_documents(
    State(state): State<AppState>,
    Path(unit_id): Path<String>,
    jar: CookieJar,
    Form(form): Form<DocumentUnlockForm>,
) -> Response {
    let Some((user, session)) = require_session(&state, &jar).await else {
        return Redirect::to("/").into_response();
    };
    if validate_csrf(&session, &form.csrf).is_err() {
        return Redirect::to(&format!("/units/{}", unit_id)).into_response();
    }

    let data = state.data.read().await;
    let policy = document_view_policy(&user, &unit_id, &data, Some(&session));
    if !policy.branch_requires_password || !verify_password(&user.password_hash, &form.password) {
        return Redirect::to(&format!("/units/{}", unit_id)).into_response();
    }
    drop(data);

    let Some(session_cookie) = jar.get("session_id") else {
        return Redirect::to(&format!("/units/{}", unit_id)).into_response();
    };
    if let Some(stored_session) = state.sessions.write().await.get_mut(session_cookie.value()) {
        stored_session
            .unlocked_document_orgs
            .insert(unit_id.clone());
    }
    Redirect::to(&format!("/units/{}", unit_id)).into_response()
}

async fn document_manager(
    State(state): State<AppState>,
    Query(query): Query<DocumentQuery>,
    jar: CookieJar,
) -> Response {
    let Some((user, _session)) = require_session(&state, &jar).await else {
        return Redirect::to("/").into_response();
    };

    let data = state.data.read().await;
    let visible_ids = visible_org_ids(&user, &data);
    let current_org_id = user.org_id.clone();
    let branch_documents: Vec<_> = data
        .documents
        .iter()
        .filter(|item| {
            current_org_id.as_deref() != Some(item.org_id.as_str())
                && visible_ids.contains(&item.org_id)
        })
        .cloned()
        .collect();
    let unit_documents: Vec<_> = data
        .documents
        .iter()
        .filter(|item| current_org_id.as_deref() == Some(item.org_id.as_str()))
        .cloned()
        .collect();
    let selected_document = query.doc.as_ref().and_then(|doc_id| {
        branch_documents
            .iter()
            .chain(unit_documents.iter())
            .find(|item| item.id == *doc_id)
            .cloned()
    });

    Html(
        render_document_manager_page(
            &user,
            &branch_documents,
            &unit_documents,
            selected_document.as_ref(),
        )
        .into_string(),
    )
    .into_response()
}

async fn download_members_csv(
    State(state): State<AppState>,
    Path(unit_id): Path<String>,
    jar: CookieJar,
    Form(form): Form<MemberExportForm>,
) -> Response {
    let Some((user, session)) = require_session(&state, &jar).await else {
        return Redirect::to("/").into_response();
    };
    if validate_csrf(&session, &form.csrf).is_err() {
        return Redirect::to(&format!("/units/{}", unit_id)).into_response();
    }
    let data = state.data.read().await;
    let Some(access) = profile_access(&user, &unit_id, &data) else {
        return Redirect::to("/").into_response();
    };
    let Some(unit) = data
        .organizations
        .iter()
        .find(|org| org.id == unit_id)
        .cloned()
    else {
        return Redirect::to("/").into_response();
    };
    let sections = build_member_sections(&unit, access, &data);
    let mut excel = String::from(
        "<html><head><meta charset=\"utf-8\"></head><body><table border=\"1\"><tr><th>Đơn vị</th><th>Họ tên</th><th>Ngày sinh</th><th>Địa chỉ</th><th>Số điện thoại</th><th>Ngày vào tổ chức</th><th>Chức vụ</th></tr>",
    );
    for section in sections {
        for member in section.members {
            excel.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                html_escape(&section.unit.name),
                html_escape(&member.full_name),
                html_escape(&member.birth_date),
                html_escape(&member.address),
                html_escape(&member.phone),
                html_escape(&member.joined_at),
                html_escape(&member.title),
            ));
        }
    }
    excel.push_str("</table></body></html>");
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/vnd.ms-excel; charset=utf-8"),
    );
    headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!(
            "attachment; filename=\"{}-members.xls\"",
            sanitize_filename(&unit_id)
        ))
        .unwrap_or_else(|_| HeaderValue::from_static("attachment")),
    );
    (StatusCode::OK, headers, excel).into_response()
}

async fn update_unit_document_preview(
    State(state): State<AppState>,
    Path((unit_id, doc_id)): Path<(String, String)>,
    jar: CookieJar,
    Form(form): Form<DocumentUpdateForm>,
) -> Response {
    let Some((user, session)) = require_session(&state, &jar).await else {
        return Redirect::to("/").into_response();
    };
    if validate_csrf(&session, &form.csrf).is_err() {
        return Redirect::to(&format!("/units/{}?doc={}", unit_id, doc_id)).into_response();
    }

    let data = state.data.read().await;
    if profile_access(&user, &unit_id, &data) != Some(ProfileAccess::Full)
        || !can_manage_org(&user, &unit_id, &data)
    {
        return Redirect::to(&format!("/units/{}", unit_id)).into_response();
    }
    let allowed_org_ids = {
        let mut ids = ancestor_ids(&data.organizations, &unit_id);
        ids.insert(unit_id.clone());
        ids
    };
    let can_edit = data
        .documents
        .iter()
        .any(|document| document.id == doc_id && allowed_org_ids.contains(&document.org_id));
    let derived_slot = derived_shared_document_slot(&doc_id, &unit_id);
    drop(data);

    if !can_edit && derived_slot.is_none() {
        return Redirect::to(&format!("/units/{}", unit_id)).into_response();
    }

    let mut data = state.data.write().await;
    if let Some(document) = data
        .documents
        .iter_mut()
        .find(|document| document.id == doc_id)
    {
        document.preview_text = form.preview_text;
        document.updated_at = now_string();
        if persist(&state, &data).is_err() {
            return internal_error("Không lưu được tài liệu.");
        }
    } else if let Some(slot_idx) = derived_slot {
        let document_id = new_id("doc");
        let document_path = state
            .storage
            .docs_dir()
            .join(format!("{}.bin", document_id));
        let (kem_ciphertext_b64, nonce_b64, encrypted) =
            match encrypt_document(&state.config.kem_public_key, form.preview_text.as_bytes()) {
                Ok(value) => value,
                Err(_) => return internal_error("Không mã hóa được tài liệu."),
            };
        if fs::write(&document_path, encrypted).is_err() {
            return internal_error("Không ghi được tài liệu đã mã hóa.");
        }
        let timestamp = now_string();
        data.documents.push(Document {
            id: document_id.clone(),
            org_id: unit_id.clone(),
            title: format!("Tài liệu chung {}", slot_idx),
            file_name: format!("tai-lieu-chung-{}.xlsx", slot_idx),
            mime_type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                .to_owned(),
            preview_text: form.preview_text,
            year: Utc::now().year(),
            encrypted_path: document_path.display().to_string(),
            kem_ciphertext_b64,
            nonce_b64,
            uploaded_at: timestamp.clone(),
            updated_at: timestamp,
        });
        if persist(&state, &data).is_err() {
            return internal_error("Không lưu được tài liệu.");
        }
        return Redirect::to(&format!("/units/{}?doc={}", unit_id, document_id)).into_response();
    }
    Redirect::to(&format!("/units/{}?doc={}", unit_id, doc_id)).into_response()
}

async fn apply_profile_document_menu_action(
    State(state): State<AppState>,
    Path((unit_id, doc_id)): Path<(String, String)>,
    jar: CookieJar,
    Form(form): Form<DocumentMenuActionForm>,
) -> Response {
    let Some((user, session)) = require_session(&state, &jar).await else {
        return Redirect::to("/").into_response();
    };
    if validate_csrf(&session, &form.csrf).is_err() {
        return Redirect::to(&format!("/units/{}?panel=branch-docs", unit_id)).into_response();
    }

    let mut data = state.data.write().await;
    if profile_access(&user, &unit_id, &data) != Some(ProfileAccess::Full)
        || !can_manage_org(&user, &unit_id, &data)
    {
        return Redirect::to(&format!("/units/{}", unit_id)).into_response();
    }

    let Some(target_idx) = data
        .documents
        .iter()
        .position(|item| item.id == doc_id && item.org_id == unit_id)
    else {
        return Redirect::to(&format!("/units/{}?panel=branch-docs", unit_id)).into_response();
    };

    match form.action.as_str() {
        "delete" => {
            let target = data.documents.remove(target_idx);
            let _ = fs::remove_file(&target.encrypted_path);
        }
        "rename" => {
            let next_name = form.value.unwrap_or_default().trim().to_owned();
            if !next_name.is_empty() {
                let updated_at = now_string();
                if let Some(item) = data.documents.get_mut(target_idx) {
                    item.file_name = next_name.clone();
                    item.title = next_name;
                    item.updated_at = updated_at;
                }
            }
        }
        "move-up" | "move-down" => {
            let mut siblings: Vec<(usize, String)> = data
                .documents
                .iter()
                .enumerate()
                .filter(|(_, item)| item.org_id == unit_id)
                .map(|(idx, item)| (idx, item.uploaded_at.clone()))
                .collect();
            siblings.sort_by(|(_, left), (_, right)| left.cmp(right));
            if let Some(pos) = siblings.iter().position(|(idx, _)| *idx == target_idx) {
                let swap_pos = if form.action == "move-up" {
                    pos.checked_sub(1)
                } else if pos + 1 < siblings.len() {
                    Some(pos + 1)
                } else {
                    None
                };
                if let Some(other_pos) = swap_pos {
                    let left_idx = siblings[pos].0;
                    let right_idx = siblings[other_pos].0;
                    let left_uploaded = data.documents[left_idx].uploaded_at.clone();
                    let right_uploaded = data.documents[right_idx].uploaded_at.clone();
                    data.documents[left_idx].uploaded_at = right_uploaded;
                    data.documents[right_idx].uploaded_at = left_uploaded;
                    let refreshed = now_string();
                    data.documents[left_idx].updated_at = refreshed.clone();
                    data.documents[right_idx].updated_at = refreshed;
                }
            }
        }
        _ => {}
    }

    if persist(&state, &data).is_err() {
        return internal_error("Không lưu được thay đổi tài liệu.");
    }
    Redirect::to(&format!("/units/{}?panel=branch-docs", unit_id)).into_response()
}

async fn push_profile_document_up(
    State(state): State<AppState>,
    Path((unit_id, doc_id)): Path<(String, String)>,
    jar: CookieJar,
    Form(form): Form<ProfileDocumentPushUpForm>,
) -> Response {
    let Some((user, session)) = require_session(&state, &jar).await else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "message": "Phiên đăng nhập đã hết hạn." })),
        )
            .into_response();
    };
    if validate_csrf(&session, &form.csrf).is_err() {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "message": "Yêu cầu không hợp lệ." })),
        )
            .into_response();
    }

    let mut data = state.data.write().await;
    if profile_access(&user, &unit_id, &data) != Some(ProfileAccess::Full)
        || !can_manage_org(&user, &unit_id, &data)
    {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "message": "Bạn không có quyền cập nhật tài liệu này." })),
        )
            .into_response();
    }

    let Some(unit) = data
        .organizations
        .iter()
        .find(|org| org.id == unit_id)
        .cloned()
    else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "message": "Không tìm thấy đơn vị hiện tại." })),
        )
            .into_response();
    };
    let Some(parent_org_id) = unit.parent_id.clone() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "message": "Đơn vị này không có cấp trên để cập nhật." })),
        )
            .into_response();
    };

    let visible_ids = tree_visible_ids(&user, &data);
    let Some(source_document) = data
        .documents
        .iter()
        .find(|document| document.id == doc_id && visible_ids.contains(&document.org_id))
        .cloned()
    else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "message": "Không tìm thấy tài liệu đang mở." })),
        )
            .into_response();
    };

    if source_document.org_id != unit_id || !is_shared_document(&source_document) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "message": "Chỉ có thể cập nhật lên cấp trên khi đang mở tài liệu đồng nhất của chính đơn vị này." })),
        )
            .into_response();
    }

    let encrypted = match fs::read(&source_document.encrypted_path) {
        Ok(bytes) => bytes,
        Err(_) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "message": "Không đọc được file nguồn để cập nhật cấp trên." }))).into_response();
        }
    };

    let updated_at = now_string();
    if let Some(target_document) = data.documents.iter_mut().find(|document| {
        document.org_id == parent_org_id
            && is_shared_document(document)
            && (document.file_name == source_document.file_name
                || document.title == source_document.title)
    }) {
        if fs::write(&target_document.encrypted_path, &encrypted).is_err() {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "message": "Không ghi được file cấp trên." })),
            )
                .into_response();
        }
        target_document.title = source_document.title.clone();
        target_document.file_name = source_document.file_name.clone();
        target_document.mime_type = source_document.mime_type.clone();
        target_document.preview_text = form.preview_text.clone();
        target_document.year = source_document.year;
        target_document.kem_ciphertext_b64 = source_document.kem_ciphertext_b64.clone();
        target_document.nonce_b64 = source_document.nonce_b64.clone();
        target_document.updated_at = updated_at.clone();
    } else {
        let new_document_id = new_id("doc");
        let target_path = state
            .storage
            .docs_dir()
            .join(format!("{}.bin", new_document_id));
        if fs::write(&target_path, &encrypted).is_err() {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "message": "Không tạo được file mới ở cấp trên." })),
            )
                .into_response();
        }
        data.documents.push(Document {
            id: new_document_id,
            org_id: parent_org_id,
            title: source_document.title.clone(),
            file_name: source_document.file_name.clone(),
            mime_type: source_document.mime_type.clone(),
            preview_text: form.preview_text.clone(),
            year: source_document.year,
            encrypted_path: target_path.display().to_string(),
            kem_ciphertext_b64: source_document.kem_ciphertext_b64.clone(),
            nonce_b64: source_document.nonce_b64.clone(),
            uploaded_at: updated_at.clone(),
            updated_at: updated_at.clone(),
        });
    }

    if persist(&state, &data).is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(
                serde_json::json!({ "message": "Không lưu được cập nhật tài liệu lên cấp trên." }),
            ),
        )
            .into_response();
    }

    (StatusCode::OK, Json(serde_json::json!({ "message": "Đã cập nhật file đang xem lên tài khoản cấp cao hơn." }))).into_response()
}

async fn sync_shared_documents(
    State(state): State<AppState>,
    Path(unit_id): Path<String>,
    jar: CookieJar,
    Form(form): Form<SharedDocumentSyncForm>,
) -> Response {
    let Some((user, session)) = require_session(&state, &jar).await else {
        return Redirect::to("/").into_response();
    };
    if validate_csrf(&session, &form.csrf).is_err() {
        return Redirect::to(&format!("/units/{}?panel=branch-docs", unit_id)).into_response();
    }

    let mut data = state.data.write().await;
    if profile_access(&user, &unit_id, &data) != Some(ProfileAccess::Full)
        || !can_manage_org(&user, &unit_id, &data)
    {
        return Redirect::to(&format!("/units/{}", unit_id)).into_response();
    }

    let mut direct_units = direct_children(&data.organizations, &unit_id);
    direct_units.sort_by(|left, right| org_sort_key(&left.name).cmp(&org_sort_key(&right.name)));
    if direct_units.is_empty() {
        return Redirect::to(&format!("/units/{}?panel=branch-docs", unit_id)).into_response();
    }

    let selected_methods: HashMap<usize, String> = form
        .methods_json
        .as_deref()
        .and_then(|raw| serde_json::from_str::<HashMap<String, String>>(raw).ok())
        .map(|map| {
            map.into_iter()
                .filter_map(|(key, value)| key.parse::<usize>().ok().map(|index| (index, value)))
                .collect()
        })
        .unwrap_or_default();

    let documents_snapshot = data.documents.clone();
    let mut child_docs_by_unit: Vec<(String, Vec<Document>)> = Vec::new();
    for org in &direct_units {
        let mut docs: Vec<_> = documents_snapshot
            .iter()
            .filter(|item| item.org_id == org.id)
            .cloned()
            .collect();
        docs.sort_by(|left, right| {
            left.uploaded_at
                .cmp(&right.uploaded_at)
                .then_with(|| left.file_name.cmp(&right.file_name))
        });
        child_docs_by_unit.push((org.name.clone(), docs));
    }

    let mut shared_docs: Vec<_> = documents_snapshot
        .iter()
        .filter(|item| item.org_id == unit_id && is_shared_document(item))
        .cloned()
        .collect();
    shared_docs.sort_by(|left, right| {
        left.uploaded_at
            .cmp(&right.uploaded_at)
            .then_with(|| left.file_name.cmp(&right.file_name))
    });

    let max_slots = child_docs_by_unit
        .iter()
        .map(|(_, docs)| docs.len())
        .max()
        .unwrap_or(0);
    if max_slots == 0 {
        return Redirect::to(&format!("/units/{}?panel=branch-docs", unit_id)).into_response();
    }

    for slot_idx in 0..max_slots {
        let mut slot_docs: Vec<(String, Document)> = Vec::new();
        for (org_name, docs) in &child_docs_by_unit {
            if let Some(doc) = docs.get(slot_idx) {
                slot_docs.push((org_name.clone(), doc.clone()));
            }
        }
        if slot_docs.is_empty() {
            continue;
        }

        let method = selected_methods
            .get(&(slot_idx + 1))
            .cloned()
            .unwrap_or_else(|| "Theo đơn vị".to_owned());
        let aggregated_preview = aggregate_shared_slot_preview(&slot_docs, &method);
        let aggregated_bytes = aggregated_preview.as_bytes();
        let (kem_ciphertext_b64, nonce_b64, encrypted) =
            match encrypt_document(&state.config.kem_public_key, aggregated_bytes) {
                Ok(value) => value,
                Err(_) => return internal_error("Không mã hóa được tài liệu tổng hợp."),
            };

        if let Some(existing) = shared_docs.get(slot_idx) {
            if fs::write(&existing.encrypted_path, encrypted).is_err() {
                return internal_error("Không cập nhật được tệp tài liệu tổng hợp.");
            }
            if let Some(target) = data
                .documents
                .iter_mut()
                .find(|item| item.id == existing.id)
            {
                target.preview_text = aggregated_preview;
                target.mime_type =
                    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet".to_owned();
                target.kem_ciphertext_b64 = kem_ciphertext_b64;
                target.nonce_b64 = nonce_b64;
                target.updated_at = now_string();
            }
        } else {
            let document_id = new_id("doc");
            let document_path = state
                .storage
                .docs_dir()
                .join(format!("{}.bin", document_id));
            if fs::write(&document_path, encrypted).is_err() {
                return internal_error("Không tạo được tệp tài liệu tổng hợp.");
            }
            let uploaded_at = now_string();
            data.documents.push(Document {
                id: document_id,
                org_id: unit_id.clone(),
                title: format!("Tài liệu chung {}", slot_idx + 1),
                file_name: format!("tai-lieu-chung-{}.xlsx", slot_idx + 1),
                mime_type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                    .to_owned(),
                preview_text: aggregated_preview,
                year: Utc::now().year(),
                encrypted_path: document_path.display().to_string(),
                kem_ciphertext_b64,
                nonce_b64,
                uploaded_at: uploaded_at.clone(),
                updated_at: uploaded_at,
            });
        }
    }

    if persist(&state, &data).is_err() {
        return internal_error("Không lưu được tài liệu tổng hợp.");
    }
    Redirect::to(&format!("/units/{}?panel=branch-docs", unit_id)).into_response()
}

async fn update_member(
    State(state): State<AppState>,
    Path((unit_id, member_id)): Path<(String, String)>,
    jar: CookieJar,
    Form(form): Form<MemberUpdateForm>,
) -> Response {
    let Some((user, session)) = require_session(&state, &jar).await else {
        return Redirect::to("/").into_response();
    };
    if validate_csrf(&session, &form.csrf).is_err() {
        return Redirect::to("/").into_response();
    }
    let data = state.data.read().await;
    if profile_access(&user, &unit_id, &data) != Some(ProfileAccess::Full)
        || !can_manage_org(&user, &unit_id, &data)
    {
        return Redirect::to("/").into_response();
    }
    drop(data);

    let mut data = state.data.write().await;
    if let Some(member) = data
        .members
        .iter_mut()
        .find(|member| member.id == member_id && member.org_id == unit_id)
    {
        member.full_name = form.full_name;
        member.title = form.title;
        if !form.birth_date.is_empty() {
            member.birth_date = form.birth_date;
        }
        if !form.address.is_empty() {
            member.address = form.address;
        }
        if !form.phone.is_empty() {
            member.phone = form.phone;
        }
        if !form.joined_at.is_empty() {
            member.joined_at = form.joined_at;
        }
        if !form.notes.is_empty() {
            member.notes = form.notes;
        }
        member.active = form.active.is_some();
        member.updated_at = now_string();
    }
    if persist(&state, &data).is_err() {
        return internal_error("Không cập nhật được thành viên.");
    }
    if form.return_to.is_empty() {
        Redirect::to(&format!("/units/{}", unit_id)).into_response()
    } else {
        redirect_back(&form.return_to)
    }
}

async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<LoginForm>,
) -> Response {
    let username_key = form.username.trim().to_ascii_lowercase();
    if let Some(wait_state) = active_login_wait_state(&state, &username_key).await {
        return Html(render_login(false, None, Some(wait_state)).into_string()).into_response();
    }

    let data = state.data.read().await;
    let Some(user) = data
        .users
        .iter()
        .find(|item| item.username == form.username && item.active)
        .cloned()
    else {
        drop(data);
        // Constant-time: always call verify_password to prevent username enumeration via timing
        let _ = verify_password("$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", &form.password);
        let wait_state = register_login_failure(&state, &username_key).await;
        return Html(render_login(true, None, wait_state).into_string()).into_response();
    };
    let password_ok = verify_password(&user.password_hash, &form.password);
    drop(data);
    if !password_ok {
        let wait_state = register_login_failure(&state, &username_key).await;
        return Html(render_login(true, None, wait_state).into_string()).into_response();
    }

    state.login_attempts.write().await.remove(&username_key);

    let session_id = random_token(32);
    let csrf_token = random_token(24);
    state.sessions.write().await.insert(
        session_id.clone(),
        SessionState {
            user_id: user.id.clone(),
            csrf_token,
            unlocked_document_orgs: HashSet::new(),
        },
    );

    let cookie = Cookie::build(("session_id", session_id))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Strict)
        .secure(state.config.require_https)
        .build();

    (jar.add(cookie), Redirect::to("/")).into_response()
}

async fn logout(State(state): State<AppState>, jar: CookieJar) -> Response {
    if let Some(cookie) = jar.get("session_id") {
        state.sessions.write().await.remove(cookie.value());
    }
    let removal = Cookie::build(("session_id", ""))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Strict)
        .secure(state.config.require_https)
        .build();
    (jar.remove(removal), Redirect::to("/")).into_response()
}

async fn create_root_org(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<OrgForm>,
) -> Response {
    let Some((user, session)) = require_session(&state, &jar).await else {
        return Redirect::to("/").into_response();
    };
    if let Err(message) = validate_csrf(&session, &form.csrf) {
        return Html(render_login(true, Some(message), None).into_string()).into_response();
    }
    if user.role != UserRole::RootAdmin
        || !user.tree_key_enabled
        || form.admin_key != state.config.tree_admin_key
    {
        return Redirect::to("/").into_response();
    }

    let mut data = state.data.write().await;
    if data.users.iter().any(|item| item.username == form.username) {
        return Redirect::to("/").into_response();
    }
    let org_id = new_id("org");
    data.organizations.push(Organization {
        id: org_id.clone(),
        parent_id: None,
        name: form.name,
        tier: form.tier,
        category: form.category,
        active: true,
        created_at: now_string(),
        updated_at: now_string(),
    });
    data.users.push(User {
        id: new_id("user"),
        username: form.username,
        password_hash: match hash_password(&form.password) {
            Ok(hash) => hash,
            Err(_) => return internal_error("Không tạo được tài khoản quản lý."),
        },
        role: UserRole::from_value(&form.role),
        org_id: Some(org_id),
        tree_key_enabled: form.tree_key_enabled.is_some(),
        active: true,
        created_at: now_string(),
    });
    if persist(&state, &data).is_err() {
        return internal_error("Không lưu được dữ liệu tổ chức.");
    }
    redirect_back(&form.return_to)
}

async fn create_child_org(
    State(state): State<AppState>,
    Path(parent_id): Path<String>,
    jar: CookieJar,
    Form(form): Form<OrgForm>,
) -> Response {
    let Some((user, session)) = require_session(&state, &jar).await else {
        return Redirect::to("/").into_response();
    };
    if validate_csrf(&session, &form.csrf).is_err() {
        return Redirect::to("/").into_response();
    }

    let mut data = state.data.write().await;
    if !can_manage_tree(
        &user,
        &parent_id,
        &data,
        &state.config.tree_admin_key,
        &form.admin_key,
    ) {
        return Redirect::to("/").into_response();
    }
    if data.users.iter().any(|item| item.username == form.username) {
        return Redirect::to("/").into_response();
    }

    let org_id = new_id("org");
    data.organizations.push(Organization {
        id: org_id.clone(),
        parent_id: Some(parent_id),
        name: form.name,
        tier: form.tier,
        category: form.category,
        active: true,
        created_at: now_string(),
        updated_at: now_string(),
    });
    data.users.push(User {
        id: new_id("user"),
        username: form.username,
        password_hash: match hash_password(&form.password) {
            Ok(hash) => hash,
            Err(_) => return internal_error("Không tạo được tài khoản quản lý cho nhánh."),
        },
        role: UserRole::from_value(&form.role),
        org_id: Some(org_id),
        tree_key_enabled: form.tree_key_enabled.is_some(),
        active: true,
        created_at: now_string(),
    });
    if persist(&state, &data).is_err() {
        return internal_error("Không lưu được nhánh tổ chức.");
    }
    redirect_back(&form.return_to)
}

async fn add_member(
    State(state): State<AppState>,
    Path(org_id): Path<String>,
    jar: CookieJar,
    Form(form): Form<MemberForm>,
) -> Response {
    let Some((user, session)) = require_session(&state, &jar).await else {
        return Redirect::to("/").into_response();
    };
    if validate_csrf(&session, &form.csrf).is_err() {
        return Redirect::to("/").into_response();
    }

    let mut data = state.data.write().await;
    if !can_manage_org(&user, &org_id, &data) {
        return Redirect::to("/").into_response();
    }
    let fallback_index = data.members.len() % 5;
    data.members.push(Member {
        id: new_id("member"),
        org_id,
        full_name: form.full_name,
        title: form.title,
        year: form.year,
        active: true,
        notes: form.notes,
        birth_date: if form.birth_date.is_empty() {
            seed_birth_date(0, fallback_index)
        } else {
            form.birth_date
        },
        address: if form.address.is_empty() {
            "Khu vực nội bộ".to_owned()
        } else {
            form.address
        },
        phone: if form.phone.is_empty() {
            seed_phone(0, fallback_index)
        } else {
            form.phone
        },
        joined_at: if form.joined_at.is_empty() {
            format!("{}-01-01", form.year)
        } else {
            form.joined_at
        },
        updated_at: now_string(),
    });
    if persist(&state, &data).is_err() {
        return internal_error("Không lưu được thành viên.");
    }
    redirect_back(&form.return_to)
}

async fn add_activity(
    State(state): State<AppState>,
    Path(org_id): Path<String>,
    jar: CookieJar,
    Form(form): Form<ActivityForm>,
) -> Response {
    let Some((user, session)) = require_session(&state, &jar).await else {
        return Redirect::to("/").into_response();
    };
    if validate_csrf(&session, &form.csrf).is_err() {
        return Redirect::to("/").into_response();
    }

    let mut data = state.data.write().await;
    if !can_manage_org(&user, &org_id, &data) {
        return Redirect::to("/").into_response();
    }
    data.activities.push(Activity {
        id: new_id("activity"),
        org_id,
        title: form.title,
        year: form.year,
        status: ActivityStatus::from_value(&form.status),
        summary: form.summary,
        reviewed: false,
        updated_at: now_string(),
    });
    if persist(&state, &data).is_err() {
        return internal_error("Không lưu được hoạt động.");
    }
    redirect_back(&form.return_to)
}

async fn review_activity(
    State(state): State<AppState>,
    Path(activity_id): Path<String>,
    jar: CookieJar,
    Form(form): Form<CsrfForm>,
) -> Response {
    let Some((user, session)) = require_session(&state, &jar).await else {
        return Redirect::to("/").into_response();
    };
    if validate_csrf(&session, &form.csrf).is_err() {
        return Redirect::to("/").into_response();
    }
    let mut data = state.data.write().await;
    let Some(position) = data
        .activities
        .iter()
        .position(|item| item.id == activity_id)
    else {
        return Redirect::to("/").into_response();
    };
    if !visible_org_ids(&user, &data).contains(&data.activities[position].org_id) {
        return Redirect::to("/").into_response();
    }
    data.activities[position].reviewed = true;
    data.activities[position].updated_at = now_string();
    if persist(&state, &data).is_err() {
        return internal_error("Không cập nhật được trạng thái kiểm tra.");
    }
    redirect_back(&form.return_to)
}

async fn create_user(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<UserForm>,
) -> Response {
    let Some((user, session)) = require_session(&state, &jar).await else {
        return Redirect::to("/").into_response();
    };
    if validate_csrf(&session, &form.csrf).is_err() || user.role != UserRole::RootAdmin {
        return Redirect::to("/").into_response();
    }
    let mut data = state.data.write().await;
    if data.users.iter().any(|item| item.username == form.username) {
        return Redirect::to("/").into_response();
    }
    data.users.push(User {
        id: new_id("user"),
        username: form.username,
        password_hash: match hash_password(&form.password) {
            Ok(hash) => hash,
            Err(_) => return internal_error("Không tạo được mật khẩu người dùng."),
        },
        role: UserRole::from_value(&form.role),
        org_id: if form.org_id.is_empty() {
            None
        } else {
            Some(form.org_id)
        },
        tree_key_enabled: form.tree_key_enabled.is_some(),
        active: true,
        created_at: now_string(),
    });
    if persist(&state, &data).is_err() {
        return internal_error("Không lưu được người dùng.");
    }
    redirect_back(&form.return_to)
}

async fn update_dashboard_tree_user_credentials(
    State(state): State<AppState>,
    Path(org_id): Path<String>,
    jar: CookieJar,
    Form(form): Form<TreeUserCredentialForm>,
) -> Response {
    let Some((user, session)) = require_session(&state, &jar).await else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if validate_csrf(&session, &form.csrf).is_err() {
        return StatusCode::FORBIDDEN.into_response();
    }

    let username = form.username.trim();
    let password = form.password.trim();
    if username.is_empty() || password.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(TreeUserCredentialResponse {
                username: username.to_owned(),
                message: "Tài khoản và mật khẩu không được để trống.".to_owned(),
            }),
        )
            .into_response();
    }

    let mut data = state.data.write().await;
    if !data.organizations.iter().any(|org| org.id == org_id) {
        return StatusCode::NOT_FOUND.into_response();
    }

    let visible_ids = tree_visible_ids(&user, &data);
    if !visible_ids.contains(&org_id) {
        return StatusCode::FORBIDDEN.into_response();
    }

    let Some(user_index) = data
        .users
        .iter()
        .position(|item| item.org_id.as_deref() == Some(org_id.as_str()) && item.active)
    else {
        return StatusCode::NOT_FOUND.into_response();
    };

    if data
        .users
        .iter()
        .enumerate()
        .any(|(index, item)| index != user_index && item.username == username)
    {
        return (
            StatusCode::CONFLICT,
            Json(TreeUserCredentialResponse {
                username: username.to_owned(),
                message: "Tài khoản đã tồn tại.".to_owned(),
            }),
        )
            .into_response();
    }

    let password_hash = match hash_password(password) {
        Ok(hash) => hash,
        Err(_) => return internal_error("Không mã hóa được mật khẩu mới."),
    };

    let saved_username;
    {
        let target_user = &mut data.users[user_index];
        target_user.username = username.to_owned();
        target_user.password_hash = password_hash;
        saved_username = target_user.username.clone();
    }

    if persist(&state, &data).is_err() {
        return internal_error("Không lưu được tài khoản trên cây.");
    }

    (
        StatusCode::OK,
        Json(TreeUserCredentialResponse {
            username: saved_username,
            message: "Đã cập nhật tài khoản trên cây.".to_owned(),
        }),
    )
        .into_response()
}

async fn update_dashboard_tree_state(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<DashboardTreeStateForm>,
) -> Response {
    let Some((user, session)) = require_session(&state, &jar).await else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if validate_csrf(&session, &form.csrf).is_err() {
        return StatusCode::FORBIDDEN.into_response();
    }
    if form.snapshot.len() > 512_000
        || serde_json::from_str::<serde_json::Value>(&form.snapshot).is_err()
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "message": "Dữ liệu giao diện không hợp lệ." })),
        )
            .into_response();
    }

    let key = dashboard_tree_state_key(&user);
    let mut states = state.dashboard_tree_states.write().await;
    states.insert(key, form.snapshot);
    if let Err(err) = save_dashboard_tree_states(&state.dashboard_tree_state_path, &states) {
        error!(error = %err, "failed to persist dashboard tree state");
        return internal_error("Không lưu được giao diện chính.");
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({ "message": "Đã lưu giao diện chính." })),
    )
        .into_response()
}

async fn upload_document(
    State(state): State<AppState>,
    jar: CookieJar,
    mut multipart: Multipart,
) -> Response {
    let Some((user, session)) = require_session(&state, &jar).await else {
        return Redirect::to("/").into_response();
    };

    let mut form_map = HashMap::new();
    let mut file_bytes = Vec::new();
    let mut file_name = String::from("tai-lieu.bin");
    let mut mime_type = String::from("application/octet-stream");
    while let Some(field) = multipart.next_field().await.unwrap_or(None) {
        let name = field.name().unwrap_or_default().to_owned();
        if name == "document" {
            file_name = field.file_name().unwrap_or("tai-lieu.bin").to_owned();
            mime_type = field
                .content_type()
                .unwrap_or("application/octet-stream")
                .to_owned();
            file_bytes = field.bytes().await.unwrap_or_default().to_vec();
        } else {
            form_map.insert(name, field.text().await.unwrap_or_default());
        }
    }
    if validate_csrf(
        &session,
        form_map.get("csrf").map(String::as_str).unwrap_or_default(),
    )
    .is_err()
    {
        return Redirect::to("/").into_response();
    }

    let org_id = form_map.get("org_id").cloned().unwrap_or_default();
    let return_target = form_map
        .get("return_to")
        .and_then(|value| sanitize_local_return_target(value));
    let data = state.data.read().await;
    if file_bytes.is_empty()
        || profile_access(&user, &org_id, &data).is_none()
        || !can_upload_documents(&data.organizations, &org_id)
    {
        return Redirect::to("/").into_response();
    }
    drop(data);

    let title = form_map
        .get("title")
        .cloned()
        .unwrap_or_else(|| "tai-lieu".to_owned());
    let year = form_map
        .get("year")
        .and_then(|value| value.parse::<i32>().ok())
        .unwrap_or(chrono::Utc::now().year());
    let preview_text = build_document_preview(&file_bytes, &file_name);

    let (kem_ciphertext_b64, nonce_b64, encrypted) =
        match encrypt_document(&state.config.kem_public_key, &file_bytes) {
            Ok(value) => value,
            Err(_) => return internal_error("Không mã hóa được tài liệu."),
        };

    let mut data = state.data.write().await;
    let uploaded_at = now_string();
    if let Some(existing) = data.documents.iter_mut().find(|document| {
        document.org_id == org_id
            && document.file_name == file_name
            && !is_shared_document(document)
    }) {
        if fs::write(&existing.encrypted_path, encrypted).is_err() {
            return internal_error("Không ghi được tài liệu đã mã hóa.");
        }
        existing.title = title;
        existing.mime_type = mime_type;
        existing.preview_text = preview_text;
        existing.year = year;
        existing.kem_ciphertext_b64 = kem_ciphertext_b64;
        existing.nonce_b64 = nonce_b64;
        existing.uploaded_at = uploaded_at.clone();
        existing.updated_at = uploaded_at;
        if persist(&state, &data).is_err() {
            return internal_error("Không lưu được metadata tài liệu.");
        }
        return Redirect::to(return_target.as_deref().unwrap_or("/")).into_response();
    }

    let document_id = new_id("doc");
    let document_path = state
        .storage
        .docs_dir()
        .join(format!("{}.bin", document_id));
    if fs::write(&document_path, encrypted).is_err() {
        return internal_error("Không ghi được tài liệu đã mã hóa.");
    }

    data.documents.push(Document {
        id: document_id,
        org_id,
        title,
        file_name,
        mime_type,
        preview_text,
        year,
        encrypted_path: document_path.display().to_string(),
        kem_ciphertext_b64,
        nonce_b64,
        uploaded_at: uploaded_at.clone(),
        updated_at: uploaded_at,
    });
    if persist(&state, &data).is_err() {
        return internal_error("Không lưu được metadata tài liệu.");
    }
    Redirect::to(return_target.as_deref().unwrap_or("/")).into_response()
}

fn sanitize_local_return_target(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.starts_with('/') && !trimmed.starts_with("//") {
        Some(trimmed.to_owned())
    } else {
        None
    }
}

async fn download_document(
    State(state): State<AppState>,
    Path(document_id): Path<String>,
    jar: CookieJar,
    Form(form): Form<DownloadForm>,
) -> Response {
    let Some((user, session)) = require_session(&state, &jar).await else {
        return Redirect::to("/").into_response();
    };
    let data = state.data.read().await;
    let Some(document) = data
        .documents
        .iter()
        .find(|item| item.id == document_id)
        .cloned()
    else {
        return internal_error("Không tìm thấy tài liệu.");
    };
    let can_download = if user.role == UserRole::RootAdmin {
        true
    } else if let Some(user_org_id) = user.org_id.as_deref() {
        if user_org_id == document.org_id {
            true
        } else if descendant_ids(&data.organizations, user_org_id).contains(&document.org_id) {
            false
        } else if ancestor_ids(&data.organizations, user_org_id).contains(&document.org_id) {
            session.unlocked_document_orgs.contains(&document.org_id)
        } else {
            false
        }
    } else {
        false
    };
    if !can_download {
        return Redirect::to("/").into_response();
    }
    let encrypted = match fs::read(&document.encrypted_path) {
        Ok(value) => value,
        Err(_) => return internal_error("Không đọc được tài liệu đã mã hóa."),
    };
    let decrypted = match decrypt_document(
        &form.access_key,
        &document.kem_ciphertext_b64,
        &document.nonce_b64,
        &encrypted,
    ) {
        Ok(value) => value,
        Err(_) => return internal_error("Khóa giải mã không hợp lệ hoặc dữ liệu đã bị thay đổi."),
    };

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    let disposition = format!(
        "attachment; filename=\"{}-{}.bin\"",
        sanitize_filename(&document.title),
        document.year
    );
    let Ok(value) = HeaderValue::from_str(&disposition) else {
        return internal_error("Không tạo được phản hồi tải tài liệu.");
    };
    headers.insert(header::CONTENT_DISPOSITION, value);
    (StatusCode::OK, headers, decrypted).into_response()
}

async fn render_dashboard(
    state: &AppState,
    user: &User,
    session: Option<SessionState>,
    query: &DocumentQuery,
) -> Html<String> {
    let data = state.data.read().await;
    let network_settings = state.network_settings.read().await.clone();
    let picker_visible_ids = visible_org_ids(user, &data);
    let csrf = session.map(|item| item.csrf_token).unwrap_or_default();
    let picker_organizations: Vec<Organization> = data
        .organizations
        .iter()
        .filter(|org| picker_visible_ids.contains(&org.id))
        .cloned()
        .collect();
    let current_org = user
        .org_id
        .as_ref()
        .and_then(|org_id| data.organizations.iter().find(|org| &org.id == org_id))
        .cloned();
    let dashboard_org = current_org.clone().or_else(|| {
        if user.role == UserRole::RootAdmin {
            data.organizations.iter().find(|org| org.tier == 0).cloned()
        } else {
            None
        }
    });
    let _unit_label = current_org
        .as_ref()
        .map(|org| org.name.clone())
        .unwrap_or_else(|| user.username.clone());
    let displayed_organizations = dashboard_graph_organizations(user, &data.organizations);
    let initial_panel = query.panel.as_deref().unwrap_or_default();
    let tree_user_map = json_value_for_inline_script(
        &data
            .organizations
            .iter()
            .filter_map(|org| {
                effective_org_user_credentials(&data, &org.id).map(|(username, _password)| {
                    (
                        org.id.clone(),
                        DashboardTreeUserRecord {
                            username,
                            password: String::new(),
                        },
                    )
                })
            })
            .collect::<HashMap<String, DashboardTreeUserRecord>>(),
    );
    let tree_state_key = dashboard_tree_state_key(user);
    let dashboard_tree_state = state
        .dashboard_tree_states
        .read()
        .await
        .get(&tree_state_key)
        .cloned()
        .unwrap_or_default();
    let dashboard_tree_state_json = json_for_inline_script(&dashboard_tree_state);
    let mut report_source_units = picker_organizations;
    report_source_units.sort_by_key(|org| (org.tier, org_sort_key(&org.name)));
    let report_units: Vec<_> = report_source_units
        .iter()
        .map(|org| build_dashboard_report_record(org, &data))
        .collect();
    let report_units_json = json_value_for_inline_script(&report_units);

    // Header lineage block: top-tier ancestor / parent / self.
    // Falls back gracefully when the user has no org or is at the top level.
    let markup = html! {
        (DOCTYPE)
        html {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { "Website nội bộ tổ chức" }
                link rel="icon" type="image/svg+xml" href="/assets/emblem.svg";
                link rel="stylesheet" href=(static_assets().base_css_url);
                script src=(static_assets().sync_js_url) defer {}
                script src=(static_assets().dashboard_js_url) defer {}
            }
            body data-panel-root="dashboard" data-initial-panel=(initial_panel) data-sync-username=(&user.username) data-tree-edit-admin=(user.role == UserRole::RootAdmin) data-tree-csrf=(&csrf) data-dashboard-org-id=(dashboard_org.as_ref().map(|org| org.id.as_str()).unwrap_or_default()) {
                main class="shell command-shell" {
                    img class="site-top-banner dashboard-top-banner" src="/assets/site-bg.png" alt="Quân khu 5";
                    section class="graph-stage minimal-stage" {
                        div class="floating-controls" {
                            div class="top-control-row" {
                                div class="panel-shell" data-panel="settings" {
                                    button type="button" class="icon-button dashboard-control-button panel-trigger" data-panel-toggle="settings" aria-label="Cài đặt" title="Cài đặt" { "⚙" }
                                    div class="icon-panel compact-panel settings-panel" {
                                        @if user.role == UserRole::RootAdmin {
                                            button type="button" class="tree-edit-mode-btn settings-action-button" data-tree-edit-toggle="true" data-editing="false" aria-label="Chỉnh sửa giao diện" title="Chỉnh sửa giao diện" { "Chỉnh sửa giao diện" }
                                            div class="lan-mode-toggle" {
                                                button type="button" class="lan-mode-button" data-lan-toggle="true" data-is-lan=(network_settings.mode == NetworkMode::LanOnly) title="Chế độ LAN" { "LAN" }
                                                button type="button" class="lan-edit-btn" data-ip-toggle="true" aria-label="Chỉnh sửa IP" title="Chỉnh sửa IP" style="width:34px; height:30px; flex:0 0 34px; padding:0; display:flex; align-items:center; justify-content:center;" {
                                                        svg viewBox="0 0 24 24" width="18" height="18" style="display:block; width:18px; height:18px; fill:currentColor;" aria-hidden="true" {
                                                        path d="M6.25 7.5a2.25 2.25 0 1 1 4.5 0 2.25 2.25 0 0 1-4.5 0Zm7 0a2.25 2.25 0 1 1 4.5 0 2.25 2.25 0 0 1-4.5 0ZM5 15.25c0-1.24 1.01-2.25 2.25-2.25h2.5c1.24 0 2.25 1.01 2.25 2.25V17a.75.75 0 0 1-1.5 0v-1.75a.75.75 0 0 0-.75-.75h-2.5a.75.75 0 0 0-.75.75V17A.75.75 0 0 1 5 17v-1.75Zm8 0c0-1.24 1.01-2.25 2.25-2.25h2.5c1.24 0 2.25 1.01 2.25 2.25V17a.75.75 0 0 1-1.5 0v-1.75a.75.75 0 0 0-.75-.75h-2.5a.75.75 0 0 0-.75.75V17A.75.75 0 0 1 13 17v-1.75ZM11.25 9.5a.75.75 0 0 1 .75-.75h1.25V7.5a.75.75 0 0 1 1.5 0v1.25H16a.75.75 0 0 1 0 1.5h-1.25v1.25a.75.75 0 0 1-1.5 0v-1.25H12a.75.75 0 0 1-.75-.75Z";
                                                    }
                                                }
                                                div class="ip-whitelist-section" data-ip-section="true" {
                                                    div class="ip-list" data-ip-list="true" {
                                                        @for ip in &network_settings.ip_whitelist {
                                                            div class="ip-row" {
                                                                input type="text" class="ip-row-input" value=(ip.to_string()) spellcheck="false";
                                                                button type="button" class="remove-ip-btn" aria-label="Xóa IP" title="Xóa IP" { "×" }
                                                            }
                                                        }
                                                    }
                                                    button type="button" class="ip-add-row-btn" data-ip-add="true" aria-label="Thêm IP" title="Thêm IP" { "+" }
                                                }
                                            }
                                        } @else {
                                            div class="settings-password-wrap" {
                                                button type="button" class="tree-edit-mode-btn settings-action-button" data-tree-edit-toggle="true" data-editing="false" aria-label="Chỉnh sửa giao diện" title="Chỉnh sửa giao diện" { "Chỉnh sửa giao diện" }
                                                button type="button" class="settings-action-button" data-password-toggle="true" aria-label="Đổi mật khẩu" title="Đổi mật khẩu" {
                                                    "Đổi mật khẩu"
                                                }
                                                div class="settings-password-panel" data-password-panel="true" hidden {
                                                    input type="password" class="settings-password-input" data-password-current="true" placeholder="Mật khẩu cũ" autocomplete="current-password";
                                                    input type="password" class="settings-password-input" data-password-next="true" placeholder="Mật khẩu mới" autocomplete="new-password";
                                                    button type="button" class="settings-password-save" data-password-save="true" { "Lưu" }
                                                }
                                            }
                                        }
                                    }
                                }
                                div class="panel-shell" data-panel="user" {
                                    button type="button" class="icon-button dashboard-control-button account-control-button panel-trigger" data-panel-toggle="user" aria-label="Tài khoản" title="Tài khoản" {
                                        svg viewBox="0 0 24 24" aria-hidden="true" {
                                            path d="M12 12.4c2.72 0 4.92-2.2 4.92-4.92S14.72 2.56 12 2.56 7.08 4.76 7.08 7.48 9.28 12.4 12 12.4zm0 2.46c-3.61 0-6.54 2.93-6.54 6.54h13.08c0-3.61-2.93-6.54-6.54-6.54z";
                                        }
                                    }
                                    div class="icon-panel compact-panel compact-account-panel" {
                                        form method="post" action="/logout" class="account-logout-form" {
                                            button type="submit" class="logout-icon-btn" aria-label="Đăng xuất" title="Đăng xuất" { "Đăng xuất" }
                                        }
                                    }
                                }
                            }
                            div class="control-action-stack" {
                                div class="panel-shell" data-panel="docs" {
                                    button type="button" class="icon-button dashboard-action-button panel-trigger" data-panel-toggle="docs" aria-label="Tài liệu" title="Tài liệu" {
                                        svg viewBox="0 0 24 24" aria-hidden="true" {
                                            path d="M6 3.5h8.4L19 8.1V20a1.5 1.5 0 0 1-1.5 1.5h-11A1.5 1.5 0 0 1 5 20V5a1.5 1.5 0 0 1 1-1.42V3.5Zm8 1.9V9h3.6L14 5.4ZM8 12h8v1.6H8V12Zm0 3.1h8v1.6H8v-1.6Z";
                                        }
                                        span { "Tài liệu" }
                                    }
                                    (render_dashboard_documents_overlay())
                                }
                                div class="panel-shell" data-panel="reports" {
                                    button type="button" class="icon-button dashboard-action-button dashboard-report-button panel-trigger" data-panel-toggle="reports" aria-label="Báo cáo" title="Báo cáo" {
                                        svg viewBox="0 0 24 24" aria-hidden="true" {
                                            path d="M5 4.5h14v15H5v-15Zm2 2v11h10v-11H7Zm1.5 7.2h1.7v2.2H8.5v-2.2Zm3.1-4h1.7v6.2h-1.7V9.7Zm3.1 2.2h1.7v4h-1.7v-4Z";
                                        }
                                        span { "Báo cáo" }
                                    }
                                    div class="compact-panel dashboard-report-panel" {
                                        div class="dashboard-unit-picker report-picker" data-unit-picker="reports" data-report-picker="true" {
                                            strong { "Báo cáo" }
                                            input type="search" class="dashboard-unit-search" data-unit-search="reports" placeholder="Tìm đơn vị" autocomplete="off";
                                            div class="report-unit-list" data-report-unit-list="true" {}
                                        }
                                    }
                                }
                            }
                        }

                        article class="graph-card graph-card-minimal" {
                            div class="graph-grid" aria-hidden="true" {}
                            div class="graph-aura graph-aura-left" aria-hidden="true" {}
                            div class="graph-aura graph-aura-right" aria-hidden="true" {}
                            (render_org_tree_svg(&displayed_organizations, user))
                            script id="tree-user-map" type="application/json" { (PreEscaped(tree_user_map)) }
                            script id="tree-state-snapshot" type="application/json" { (PreEscaped(dashboard_tree_state_json)) }
                            script id="dashboard-report-data" type="application/json" { (PreEscaped(report_units_json)) }
                        }
                    }
                }
            }
        }
    };
    Html(markup.into_string())
}

struct UnitProfileView<'a> {
    user: &'a User,
    session: &'a SessionState,
    unit: &'a Organization,
    initial_panel: Option<&'a str>,
    access: ProfileAccess,
    can_upload_documents_here: bool,
    unified_documents: &'a [Document],
    unit_documents: &'a [Document],
    preview_document: Option<&'a Document>,
    document_policy: DocumentViewPolicy,
    report_record: Option<&'a DashboardReportUnitRecord>,
}

async fn render_unit_profile_page(view: UnitProfileView<'_>) -> Markup {
    let UnitProfileView {
        user,
        session,
        unit,
        initial_panel,
        access,
        can_upload_documents_here,
        unified_documents,
        unit_documents,
        preview_document,
        document_policy,
        report_record,
    } = view;
    let _is_own_profile = user.org_id.as_deref() == Some(unit.id.as_str());
    let can_edit_profile = access == ProfileAccess::Full;
    let mode_label = if initial_panel == Some("unit-report") {
        "Báo cáo"
    } else {
        "Tài liệu"
    };
    html! {
        (DOCTYPE)
        html {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { (format!("Đơn vị {}", unit.name)) }
                link rel="icon" type="image/svg+xml" href="/assets/emblem.svg";
                link rel="stylesheet" href=(static_assets().base_css_url);
                script src=(static_assets().sync_js_url) defer {}
                script src=(static_assets().profile_js_url) defer {}
            }
            body data-panel-root="profile" data-initial-panel=(initial_panel.unwrap_or_default()) data-sync-username=(&user.username) {
                main class="shell profile-shell spreadsheet-shell" {
                    div class="profile-corners" {
                        div class="left-rail" {
                            div class="nav-rail-row" {
                                button type="button" class="rail-button rail-back profile-corner-button" title="Quay lại" data-go-back="true" aria-label="Quay lại" {
                                    svg viewBox="0 0 24 24" aria-hidden="true" {
                                        path d="M9 7 4 12l5 5" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="square" stroke-linejoin="miter";
                                        path d="M5 12h10c2.761 0 5 2.239 5 5v1" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="square" stroke-linejoin="miter";
                                    }
                                }
                            }
                        }
                        div class="profile-right-tools" {
                            a href="/" class="rail-button profile-corner-button profile-home-button" title="Về trang chủ" aria-label="Về trang chủ" {
                                svg viewBox="0 0 24 24" aria-hidden="true" {
                                    path d="M12 3.5 3.5 10.8v9.7h6v-6h5v6h6v-9.7L12 3.5Z" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round";
                                    path d="M9.5 20.5h5" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round";
                                }
                            }
                        }
                    }

                    section class="sheet-layout" {
                        article class="card sheet-card" {
                            div class="sheet-head" {
                                div {
                                    @if initial_panel != Some("unit-report") && can_edit_profile {
                                        details class="doc-file-manager" {
                                            summary class="doc-file-manager-summary" {
                                                div class="sheet-title-row" {
                                                    h1 class="profile-mode-title" { (mode_label) }
                                                    span class="profile-unit-title-code" { (&unit.name) }
                                                    span class="doc-file-manager-hint" { "▾ quản lý tệp" }
                                                }
                                            }
                                            (render_doc_file_manager(unit_documents, unit, &session.csrf_token, can_upload_documents_here))
                                        }
                                    } @else {
                                        div class="sheet-title-row" {
                                            h1 class="profile-mode-title" { (mode_label) }
                                            span class="profile-unit-title-code" { (&unit.name) }
                                        }
                                    }
                                }
                                div class="sheet-actions" {
                                    @if access == ProfileAccess::Limited && initial_panel != Some("unit-report") {
                                        span class="compact-tag" { "3 thành viên chủ chốt" }
                                    }
                                }
                            }
                            @if initial_panel == Some("unit-report") {
                                @if let Some(report_record) = report_record {
                                    (render_profile_report_workspace(report_record, unit))
                                }
                            } @else if document_policy.can_view_branch || document_policy.can_view_unit {
                                (render_profile_document_workspace(ProfileDocumentWorkspaceView {
                                    unified_documents,
                                    unit_documents,
                                    selected_document: preview_document,
                                    unit,
                                    csrf: &session.csrf_token,
                                    can_edit: can_edit_profile,
                                    unit_is_leaf: can_upload_documents_here,
                                }))
                            }
                        }
                    }
                }
            }
        }
    }
}

fn render_dashboard_documents_overlay() -> Markup {
    html! {
        div class="compact-panel dashboard-documents-panel" {
            div class="dashboard-unit-picker" data-unit-picker="docs" {
                strong { "Tài liệu" }
                div class="dashboard-doc-panel-toolbar" {
                    label class="dashboard-doc-upload-link" title="Tải lên danh sách" {
                        "Tải lên"
                        input type="file" class="dashboard-doc-upload-input" data-dashboard-doc-upload="true" accept=".xlsx,.xlxs,.csv,.txt" hidden;
                    }
                    button type="button" class="dashboard-doc-search-icon" data-dashboard-doc-search-toggle="true" title="Tìm đơn vị" aria-label="Tìm đơn vị" { "⌕" }
                }
                input type="search" class="dashboard-unit-search dashboard-unit-search-collapsed" data-unit-search="docs" placeholder="Tìm đơn vị" autocomplete="off" hidden;
                div class="report-unit-list dashboard-doc-unit-list" data-doc-unit-list="true" {}
            }
        }
    }
}

const REPORT_CHART_COLORS: [&str; 6] = [
    "#111111", "#2563eb", "#16a34a", "#f59e0b", "#dc2626", "#7c3aed",
];

fn report_bucket_percent(value: usize, total: usize) -> usize {
    if total == 0 {
        0
    } else {
        ((value as f64 / total as f64) * 100.0).round() as usize
    }
}

fn report_pie_background(buckets: &[DashboardReportBucket]) -> String {
    let total: usize = buckets.iter().map(|bucket| bucket.value).sum();
    if total == 0 {
        return "#e5e7eb".to_owned();
    }
    let mut cursor = 0.0f64;
    let mut slices = Vec::new();
    for (index, bucket) in buckets.iter().enumerate() {
        if bucket.value == 0 {
            continue;
        }
        let next = cursor + (bucket.value as f64 / total as f64) * 360.0;
        slices.push(format!(
            "{} {:.3}deg {:.3}deg",
            REPORT_CHART_COLORS[index % REPORT_CHART_COLORS.len()],
            cursor,
            next
        ));
        cursor = next;
    }
    format!("conic-gradient({})", slices.join(", "))
}

fn report_bucket_value<'a>(
    buckets: &'a [DashboardReportBucket],
    label: &str,
) -> Option<&'a DashboardReportBucket> {
    buckets.iter().find(|bucket| bucket.label == label)
}

fn report_bucket_summary(title: &str, buckets: &[DashboardReportBucket]) -> (String, String) {
    let total: usize = buckets.iter().map(|bucket| bucket.value).sum();
    if total == 0 {
        return (
            "Chưa có dữ liệu để phân tích.".to_owned(),
            "Các nhóm sẽ được cập nhật khi tài liệu có dữ liệu phù hợp.".to_owned(),
        );
    }

    let mut positive = buckets
        .iter()
        .filter(|bucket| bucket.value > 0)
        .collect::<Vec<_>>();
    positive.sort_by(|left, right| {
        right
            .value
            .cmp(&left.value)
            .then_with(|| left.label.cmp(&right.label))
    });
    let first = positive.first().copied();
    let second = positive.get(1).copied();
    let lead = match (first, second) {
        (Some(left), Some(right)) => format!(
            "Phần lớn thành viên thuộc nhóm {} chiếm {}%, và {} chiếm {}%.",
            left.label,
            report_bucket_percent(left.value, total),
            right.label,
            report_bucket_percent(right.value, total)
        ),
        (Some(left), None) => format!(
            "Toàn bộ thành viên thuộc nhóm {} với {} thành viên, chiếm {}%.",
            left.label,
            left.value,
            report_bucket_percent(left.value, total)
        ),
        _ => "Chưa có nhóm nổi bật để phân tích.".to_owned(),
    };

    let detail = if title.contains("độ tuổi") {
        let over_sixty = report_bucket_value(buckets, "60+")
            .map(|bucket| bucket.value)
            .unwrap_or(0);
        let fifty = report_bucket_value(buckets, "50-59")
            .map(|bucket| (bucket.value, report_bucket_percent(bucket.value, total)))
            .unwrap_or((0, 0));
        match (over_sixty, fifty) {
            (count, _) if count > 0 => {
                format!("Nhóm trên 60 có {count} thành viên cần được theo dõi riêng.")
            }
            (_, (count, percent)) if count > 0 => {
                format!("Nhóm 50-59 có {count} thành viên, chiếm {percent}% tổng số.")
            }
            _ => "Cơ cấu độ tuổi tập trung ở các nhóm còn lại.".to_owned(),
        }
    } else if positive.len() == 1 {
        "Toàn bộ dữ liệu tập trung ở một nhóm duy nhất.".to_owned()
    } else if let Some(lowest) = positive.last() {
        format!(
            "Nhóm thấp nhất có dữ liệu là {} với {} thành viên, chiếm {}%.",
            lowest.label,
            lowest.value,
            report_bucket_percent(lowest.value, total)
        )
    } else {
        "Chưa có dữ liệu chi tiết cho nhóm này.".to_owned()
    };

    (lead, detail)
}

fn render_report_pie_chart(title: &str, buckets: &[DashboardReportBucket]) -> Markup {
    let total: usize = buckets.iter().map(|bucket| bucket.value).sum();
    let (analysis_lead, analysis_detail) = report_bucket_summary(title, buckets);
    html! {
        section class="report-chart" {
            h4 { (title) }
            div class="report-chart-row" {
                div class="report-pie" style=(format!("background: {};", report_pie_background(buckets))) {}
                ul {
                    @for (index, bucket) in buckets.iter().enumerate() {
                        li {
                            span style=(format!("background:{}", REPORT_CHART_COLORS[index % REPORT_CHART_COLORS.len()])) {}
                            (format!("{}: {} = {}%", bucket.label, bucket.value, report_bucket_percent(bucket.value, total)))
                        }
                    }
                }
                div class="report-chart-analysis" {
                    p { (analysis_lead) }
                    p { (analysis_detail) }
                }
            }
        }
    }
}

fn render_report_document(record: &DashboardReportUnitRecord) -> Markup {
    html! {
        article class="report-document" {
            header class="report-letterhead" {
                div class="report-letterhead-emblem" aria-hidden="true" {}
                div class="report-letterhead-text" {
                    span class="report-letterhead-over" { "QUÂN KHU 5" }
                    h2 class="report-letterhead-title" { "BÁO CÁO TỔNG HỢP" }
                    p class="report-letterhead-unit" { "Đơn vị: " (&record.name) }
                }
            }
            dl {
                div { dt { "Tên đơn vị" } dd { (&record.name) } }
                div { dt { "Số lượng thành viên" } dd { (record.member_count) } }
                div { dt { "Số thành viên mới trong năm" } dd { (record.new_member_count) } }
            }
            (render_report_pie_chart("Theo độ tuổi", &record.age_buckets))
            (render_report_pie_chart("Theo trình độ", &record.education_buckets))
            (render_report_pie_chart("Mức độ hoàn thành nhiệm vụ", &record.completion_buckets))
            (render_report_pie_chart("Theo cấp bậc", &record.rank_buckets))
            section class="report-activities" {
                h4 { "Hoạt động trong nhiệm kì" }
                ol {
                    @if record.activities.is_empty() {
                        li { "Chưa có hoạt động." }
                    } @else {
                        @for activity in &record.activities {
                            li { (activity) }
                        }
                    }
                }
            }
        }
    }
}

fn render_profile_report_workspace(
    record: &DashboardReportUnitRecord,
    unit: &Organization,
) -> Markup {
    let report_file_name = format!("Bao_cao_{}.docx", unit.name);
    html! {
        div class="profile-report-workspace profile-document-workspace report-document-workspace" data-profile-report-root="true" {
            div class="xl-tab-bar report-tab-bar" {
                div class="xl-tab-strip" data-profile-report-tabs="true" data-report-default-name=(&report_file_name) {
                    div class="profile-document-tab is-active report-document-tab" data-report-tab="true" data-report-tab-id="main" {
                        button type="button" class="profile-document-tab-button" title=(&report_file_name) { (&report_file_name) }
                        button type="button" class="profile-document-tab-close" data-report-tab-close="true" title="Đóng tab" { "×" }
                    }
                    button type="button" class="xl-action-btn xl-add-tab-btn report-add-tab-btn" data-profile-report-add-tab="true" title="Mở tab mới" { "+" }
                }
                div class="xl-tab-actions report-tab-actions" {
                    a class="xl-action-btn report-word-link" data-profile-report-download="true" download=(&report_file_name) href="#" title="Tải Word" aria-label="Tải Word" { "⇩" }
                    div class="xl-search-shell" {
                        button type="button" class="xl-action-btn" data-profile-report-search-toggle="true" title="Tìm kiếm báo cáo" aria-label="Tìm kiếm báo cáo" { "⌕" }
                        div class="xl-doc-search-bar report-search-bar" data-profile-report-search-bar="true" hidden {
                            input type="search" class="xl-doc-search-input" data-profile-report-search="true" placeholder="Tìm kiếm trong báo cáo..." autocomplete="off";
                            span class="xl-doc-search-count" data-profile-report-search-count="true" aria-live="polite" {}
                            button type="button" class="xl-doc-search-close" data-profile-report-search-close="true" title="Đóng tìm kiếm" aria-label="Đóng tìm kiếm" { "×" }
                        }
                    }
                    button type="button" class="xl-action-btn xl-action-btn-edit report-edit-button" data-profile-report-edit="true" title="Chỉnh sửa báo cáo" aria-label="Chỉnh sửa báo cáo" { "✎" }
                }
            }
            div class="word-ribbon report-word-ribbon" data-profile-report-ribbon="true" hidden {
                div class="word-ribbon-group" {
                    span class="xl-group-label" { "Font" }
                    div class="xl-row" {
                        select class="xl-select xl-font-name" data-report-font="true" aria-label="Font" {
                            option value="'Times New Roman',Times,serif" selected { "Times New Roman" }
                            option value="Arial,Helvetica,sans-serif" { "Arial" }
                            option value="Cambria,Georgia,serif" { "Cambria" }
                            option value="'Segoe UI',Tahoma,sans-serif" { "Segoe UI" }
                        }
                        select class="xl-select xl-font-size" data-report-font-size="true" aria-label="Cỡ chữ" {
                            option { "10" } option selected { "12" } option { "14" } option { "16" } option { "18" } option { "20" } option { "24" }
                        }
                    }
                    div class="xl-row" {
                        button type="button" class="xl-btn xl-btn-icon" data-report-command="bold" title="In đậm" { b { "B" } }
                        button type="button" class="xl-btn xl-btn-icon" data-report-command="italic" title="In nghiêng" { i { "I" } }
                        button type="button" class="xl-btn xl-btn-icon" data-report-command="underline" title="Gạch chân" { u { "U" } }
                        span class="xl-color-wrap" title="Màu chữ" {
                            label class="xl-color-label" {
                                span { "A" }
                                input type="color" class="xl-color-input" data-report-text-color="true" value="#000000";
                            }
                        }
                    }
                }
                div class="xl-ribbon-sep" {}
                div class="word-ribbon-group" {
                    span class="xl-group-label" { "Đoạn" }
                    div class="xl-row" {
                        button type="button" class="xl-btn xl-btn-icon" data-report-command="justifyLeft" title="Căn trái" { "☰" }
                        button type="button" class="xl-btn xl-btn-icon" data-report-command="justifyCenter" title="Căn giữa" { "≡" }
                        button type="button" class="xl-btn xl-btn-icon" data-report-command="justifyRight" title="Căn phải" { "☷" }
                        button type="button" class="xl-btn xl-btn-icon" data-report-command="insertUnorderedList" title="Danh sách" { "•" }
                    }
                }
            }
            div class="report-edit-surface profile-report-surface" data-profile-report-surface="true" {
                (render_report_document(record))
            }
        }
    }
}

fn render_document_list(documents: &[Document], current_org_id: &str, href_prefix: &str) -> Markup {
    let target_prefix = if current_org_id.is_empty() {
        href_prefix.to_owned()
    } else {
        format!("/units/{current_org_id}")
    };
    html! {
        div class="document-list-card" {
            @if documents.is_empty() {
                p class="muted" { "Chưa có tài liệu." }
            } @else {
                ul class="document-name-list" {
                    @for (idx, document) in documents.iter().enumerate() {
                        li class="doc-name-row" {
                            span class="doc-row-num" { (idx + 1) }
                            a href={(format!("{}?doc={}&return_to=%2F", target_prefix, document.id))} class="document-link" {
                                span class="document-filename" { (&document.file_name) }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn render_quick_document_preview(
    document: &Document,
    current_org: Option<&Organization>,
) -> Markup {
    let target_org_id = current_org
        .map(|org| org.id.as_str())
        .unwrap_or(document.org_id.as_str());
    html! {
        div class="quick-preview-card" {
            div class="quick-preview-head" {
                strong { (&document.file_name) }
                a href={(format!("/units/{}?doc={}", target_org_id, document.id))} class="icon-button tiny-icon-button" title="Mở để chỉnh sửa" { "✎" }
            }
            div class="quick-preview-body" tabindex="0" {
                pre data-doc-id=(&document.id) data-doc-updated-at=(&document.updated_at) { (&document.preview_text) }
            }
        }
    }
}

#[derive(Serialize)]
struct ProfileDocumentTabRecord<'a> {
    id: &'a str,
    file_name: &'a str,
    mime_type: &'a str,
    preview_text: &'a str,
    updated_at: &'a str,
    kind: &'a str,
    editable: bool,
}

fn profile_document_records_json(documents: &[Document]) -> String {
    let records: Vec<_> = documents
        .iter()
        .map(|document| ProfileDocumentTabRecord {
            id: document.id.as_str(),
            file_name: document.file_name.as_str(),
            mime_type: document.mime_type.as_str(),
            preview_text: document.preview_text.as_str(),
            updated_at: document.updated_at.as_str(),
            kind: if is_shared_document(document) || is_derived_shared_document(document) {
                "synced"
            } else {
                "internal"
            },
            editable: true,
        })
        .collect();
    json_value_for_inline_script(&records)
}

struct ProfileDocumentWorkspaceView<'a> {
    unified_documents: &'a [Document],
    unit_documents: &'a [Document],
    selected_document: Option<&'a Document>,
    unit: &'a Organization,
    csrf: &'a str,
    can_edit: bool,
    unit_is_leaf: bool,
}

/// Bảng quản lý tệp tài liệu của đơn vị (mở ra khi bấm vào tiêu đề "Tài liệu ...").
/// Cho đổi tên / xóa các tệp của chính đơn vị; tải tệp mới nếu là đơn vị lá.
fn render_doc_file_manager(
    documents: &[Document],
    unit: &Organization,
    csrf: &str,
    can_upload: bool,
) -> Markup {
    let return_to = format!("/units/{}", unit.id);
    let current_year = Utc::now().year();
    let own_files: Vec<&Document> = documents
        .iter()
        .filter(|doc| {
            doc.org_id == unit.id
                && !is_shared_document(doc)
                && !is_derived_shared_document(doc)
        })
        .collect();
    html! {
        div class="doc-file-manager-panel" {
            h3 { "Quản lý tệp tài liệu" }
            @if own_files.is_empty() {
                p class="muted" { "Đơn vị này chưa có tệp tài liệu riêng." }
            } @else {
                div class="doc-file-table-wrap" {
                    table class="doc-file-table" {
                        thead { tr { th { "Tên tệp" } th { "Đổi tên" } th {} } }
                        tbody {
                            @for doc in &own_files {
                                tr {
                                    td class="doc-file-name" { (&doc.file_name) }
                                    td {
                                        form method="post" action=(format!("/units/{}/documents/{}/menu-action", unit.id, doc.id)) class="doc-file-inline-form" {
                                            input type="hidden" name="csrf" value=(csrf);
                                            input type="hidden" name="action" value="rename";
                                            input type="text" name="value" value=(&doc.file_name) class="doc-file-rename-input" required;
                                            button type="submit" class="doc-file-btn" { "Lưu" }
                                        }
                                    }
                                    td {
                                        form method="post" action=(format!("/units/{}/documents/{}/menu-action", unit.id, doc.id)) class="doc-file-inline-form" onsubmit="return confirm('Xóa tệp này?');" {
                                            input type="hidden" name="csrf" value=(csrf);
                                            input type="hidden" name="action" value="delete";
                                            button type="submit" class="doc-file-btn doc-file-btn-delete" { "Xóa" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            @if can_upload {
                form method="post" action="/documents" enctype="multipart/form-data" class="doc-file-upload-form" {
                    input type="hidden" name="csrf" value=(csrf);
                    input type="hidden" name="org_id" value=(&unit.id);
                    input type="hidden" name="year" value=(current_year);
                    input type="hidden" name="return_to" value=(&return_to);
                    input type="hidden" name="title" value="Tài liệu nội bộ";
                    label class="doc-file-add-label" {
                        span { "+ Thêm tệp (Excel/.xlsx)" }
                        input type="file" name="document" accept=".xlsx,.xls,.csv" required onchange="this.form.submit()";
                    }
                }
            } @else {
                p class="muted doc-file-note" { "Đơn vị này tổng hợp tài liệu từ cấp dưới — thêm/sửa/xóa tệp thực hiện ở đơn vị cấp dưới." }
            }
        }
    }
}

fn render_profile_document_workspace(view: ProfileDocumentWorkspaceView<'_>) -> Markup {
    let ProfileDocumentWorkspaceView {
        unified_documents,
        unit_documents,
        selected_document,
        unit,
        csrf,
        can_edit,
        unit_is_leaf,
    } = view;
    let workspace_documents = unified_documents.to_vec();

    let is_current_unit_shared = |document: &&Document| {
        document.org_id == unit.id
            && (is_shared_document(document) || is_derived_shared_document(document))
    };
    let current_unit_shared_documents: Vec<_> = unit_documents
        .iter()
        .filter(is_current_unit_shared)
        .collect();
    let current_unit_local_documents: Vec<_> = unit_documents
        .iter()
        .filter(|document| !is_current_unit_shared(document))
        .collect();

    let default_document = selected_document.or_else(|| {
        if unit_is_leaf {
            current_unit_local_documents
                .first()
                .copied()
                .or_else(|| current_unit_shared_documents.first().copied())
        } else {
            current_unit_shared_documents
                .first()
                .copied()
                .or_else(|| current_unit_local_documents.first().copied())
        }
    });
    let default_doc_id = default_document
        .map(|document| document.id.as_str())
        .unwrap_or_default();
    let initial_save_action = default_document
        .map(|document| format!("/units/{}/documents/{}", unit.id, document.id))
        .unwrap_or_else(|| format!("/units/{}", unit.id));

    let selected_doc_id = selected_document
        .filter(|document| {
            workspace_documents
                .iter()
                .any(|item| item.id == document.id)
        })
        .map(|document| document.id.as_str())
        .unwrap_or_default();
    // Merge unit_documents into workspace_documents so all docs are in the JS `docs` Map
    let mut all_records = workspace_documents.clone();
    for doc in unit_documents {
        if !all_records.iter().any(|item| item.id == doc.id) {
            all_records.push(doc.clone());
        }
    }
    let records_json = profile_document_records_json(&all_records);

    // Build the + picker data: branch docs (those in unified but not unit-only) and unit docs
    let branch_picker_sorted = {
        let mut docs: Vec<_> = current_unit_shared_documents;
        docs.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
        docs
    };
    let unit_picker_sorted = {
        let mut docs: Vec<_> = current_unit_local_documents;
        docs.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
        docs
    };

    let can_edit_leaf = can_edit && unit_is_leaf;

    html! {
        div
            class="profile-document-workspace"
            data-profile-doc-root="true"
            data-can-edit=(if can_edit_leaf { "true" } else { "false" })
            data-unit-is-leaf=(if unit_is_leaf { "true" } else { "false" })
            data-unit-id=(&unit.id)
            data-profile-doc-csrf=(csrf)
            data-default-doc-id=(default_doc_id)
            data-selected-doc-id=(selected_doc_id)
        {
            // Tab strip row with Excel download + edit buttons on right
            div class="xl-tab-bar" {
                div class="xl-tab-strip" data-profile-doc-tabs="true" {
                    // + button lives inside strip so it sits right after the last tab
                    div class="xl-doc-add-shell" data-doc-add-shell="true" {
                        button type="button" class="xl-action-btn xl-add-tab-btn" data-doc-add-toggle="true" title="Mở file" { "+" }
                        div class="xl-doc-add-dropdown" data-doc-add-panel="true" hidden {
                            div class="xl-doc-add-search-row" {
                                input type="search" class="xl-doc-add-search" data-doc-add-search="true" placeholder="Tìm theo tên…" autocomplete="off";
                            }
                            div class="xl-doc-add-results" data-doc-add-results="true" {
                                @for doc in &branch_picker_sorted {
                                    button type="button" class="xl-doc-add-item" data-doc-add-item="true" data-doc-add-id=(&doc.id) data-doc-add-name=(format!("{} {}", doc.title, doc.file_name)) {
                                        (&doc.file_name)
                                    }
                                }
                                @for doc in &unit_picker_sorted {
                                    button type="button" class="xl-doc-add-item" data-doc-add-item="true" data-doc-add-id=(&doc.id) data-doc-add-name=(format!("{} {}", doc.title, doc.file_name)) {
                                        (&doc.file_name)
                                    }
                                }
                                @if branch_picker_sorted.is_empty() && unit_picker_sorted.is_empty() {
                                    p class="xl-doc-add-empty" { "Chưa có tài liệu." }
                                }
                            }
                        }
                    }
                }
                div class="xl-tab-actions" {
                    form method="post" action={(format!("/units/{}/members/download", unit.id))} class="export-form" data-requires-online="true" {
                        input type="hidden" name="csrf" value=(csrf);
                        button type="submit" class="xl-action-btn" title="Tải Excel thành viên" { "⇩" }
                    }
                    @if can_edit && unit_is_leaf {
                        form
                            method="post"
                            action="/documents"
                            enctype="multipart/form-data"
                            class="export-form profile-toolbar-upload-form"
                            data-profile-upload-form="true"
                            data-profile-upload-kind="unit"
                            data-requires-online="true"
                        {
                            input type="hidden" name="csrf" value=(csrf);
                            input type="hidden" name="org_id" value=(&unit.id);
                            input type="hidden" name="year" value={(chrono::Utc::now().year())};
                            input type="hidden" name="return_to" value={(format!("/units/{}?panel=unit-documents", unit.id))};
                            input type="hidden" name="title" value="Tài liệu nội bộ" data-profile-upload-title="true";
                            label class="xl-action-btn profile-toolbar-upload-label" title="Tải tài liệu lên" aria-label="Tải tài liệu lên" {
                                input type="file" name="document" class="profile-empty-upload-input" data-profile-upload-input="true" required;
                                "⇧"
                            }
                        }
                    }
                    div class="xl-search-shell" {
                        button type="button" class="xl-action-btn" data-profile-doc-search-toggle="true" title="Tìm kiếm tài liệu" aria-label="Tìm kiếm tài liệu" { "⌕" }
                        div class="xl-doc-search-bar" data-profile-doc-search-bar="true" hidden {
                            input
                                type="search"
                                class="xl-doc-search-input"
                                data-profile-doc-search="true"
                                placeholder="Tìm kiếm trong tài liệu..."
                                autocomplete="off";
                            span class="xl-doc-search-count" data-profile-doc-search-count="true" aria-live="polite" {}
                            button type="button" class="xl-doc-search-close" data-profile-doc-search-close="true" title="Đóng tìm kiếm" aria-label="Đóng tìm kiếm" { "×" }
                        }
                    }
                    @if can_edit_leaf {
                        button type="button" class="xl-action-btn xl-action-btn-edit" data-profile-doc-edit-toggle="true" title="Chỉnh sửa và kiểm tra chính tả" { "✎" }
                    }
                }
            }
            // Excel-style ribbon — hidden until edit mode
            div class="xl-ribbon" data-profile-doc-ribbon="true" hidden {
                div class="xl-ribbon-group" {
                    span class="xl-group-label" { "Font" }
                    div class="xl-row" {
                        select class="xl-select xl-font-name" data-profile-doc-font="true" aria-label="Font" {
                            option value="'Times New Roman',Times,serif" selected { "Times New Roman" }
                            option value="Bahnschrift,'Segoe UI Variable Text','Trebuchet MS',sans-serif" { "Bahnschrift" }
                            option value="'Segoe UI',Tahoma,sans-serif" { "Segoe UI" }
                            option value="Arial,Helvetica,sans-serif" { "Arial" }
                            option value="Consolas,'Cascadia Code',monospace" { "Consolas" }
                            option value="Cambria,Georgia,serif" { "Cambria" }
                        }
                        select class="xl-select xl-font-size" data-xl-font-size="true" aria-label="Cỡ chữ" {
                            option { "8" } option { "9" } option { "10" } option { "11" } option selected { "12" }
                            option { "14" } option { "16" } option { "18" } option { "20" } option { "24" }
                            option { "28" } option { "32" } option { "36" } option { "48" } option { "72" }
                        }
                    }
                    div class="xl-row" {
                        button type="button" class="xl-btn xl-btn-icon" data-profile-doc-bold="true" title="In đậm (Ctrl+B)" { b { "B" } }
                        button type="button" class="xl-btn xl-btn-icon" data-profile-doc-italic="true" title="In nghiêng (Ctrl+I)" { i { "I" } }
                        button type="button" class="xl-btn xl-btn-icon" data-xl-underline="true" title="Gạch chân (Ctrl+U)" { u { "U" } }
                        button type="button" class="xl-btn xl-btn-icon" data-xl-strikethrough="true" title="Gạch ngang" { s { "S" } }
                        span class="xl-color-wrap" title="Màu chữ" {
                            label class="xl-color-label" {
                                span { "A" }
                                input type="color" class="xl-color-input" data-xl-text-color="true" value="#000000";
                            }
                        }
                        span class="xl-color-wrap" title="Màu nền ô" {
                            label class="xl-color-label xl-fill-label" {
                                span { "▣" }
                                input type="color" class="xl-color-input" data-xl-fill-color="true" value="#ffffff";
                            }
                        }
                    }
                }
                div class="xl-ribbon-sep" {}
                div class="xl-ribbon-group" {
                    span class="xl-group-label" { "Căn lề" }
                    div class="xl-row" {
                        button type="button" class="xl-btn xl-btn-icon" data-xl-align="left" title="Căn trái" { "☰" }
                        button type="button" class="xl-btn xl-btn-icon" data-xl-align="center" title="Căn giữa" { "≡" }
                        button type="button" class="xl-btn xl-btn-icon" data-xl-align="right" title="Căn phải" { "☷" }
                    }
                    div class="xl-row" {
                        button type="button" class="xl-btn xl-btn-icon" data-xl-valign="top" title="Căn trên" { "⬆" }
                        button type="button" class="xl-btn xl-btn-icon" data-xl-valign="middle" title="Căn dọc giữa" { "↕" }
                        button type="button" class="xl-btn xl-btn-icon" data-xl-valign="bottom" title="Căn dưới" { "⬇" }
                        button type="button" class="xl-btn xl-btn-icon" data-xl-wrap-text="true" title="Xuống dòng tự động" { "↵" }
                    }
                }
                div class="xl-ribbon-sep" {}
                div class="xl-ribbon-group" {
                    span class="xl-group-label" { "Số" }
                    div class="xl-row" {
                        select class="xl-select xl-num-format" data-xl-num-format="true" aria-label="Định dạng số" {
                            option value="text" selected { "Văn bản" }
                            option value="number" { "Số" }
                            option value="currency" { "Tiền tệ" }
                            option value="percent" { "Phần trăm" }
                            option value="date" { "Ngày" }
                        }
                    }
                    div class="xl-row" {
                        button type="button" class="xl-btn" data-xl-format-currency="true" title="Định dạng tiền tệ" { "$" }
                        button type="button" class="xl-btn" data-xl-format-percent="true" title="Định dạng phần trăm" { "%" }
                        button type="button" class="xl-btn" data-xl-format-comma="true" title="Thêm dấu phân cách nghìn" { "," }
                        button type="button" class="xl-btn" data-xl-increase-decimal="true" title="Tăng chữ số thập phân" { ".0+" }
                        button type="button" class="xl-btn" data-xl-decrease-decimal="true" title="Giảm chữ số thập phân" { ".0-" }
                    }
                }
                div class="xl-ribbon-sep" {}
                div class="xl-ribbon-group" {
                    span class="xl-group-label" { "Ô" }
                    div class="xl-row" {
                        button type="button" class="xl-btn" data-profile-doc-add-row="true" title="Chèn dòng" { "+↔" }
                        button type="button" class="xl-btn" data-xl-del-row="true" title="Xóa dòng" { "−↔" }
                        button type="button" class="xl-btn" data-profile-doc-add-col="true" title="Chèn cột" { "+↕" }
                        button type="button" class="xl-btn" data-xl-del-col="true" title="Xóa cột" { "−↕" }
                        button type="button" class="xl-btn" data-xl-merge="true" title="Gộp ô" { "⊞" }
                    }
                }
                div class="xl-ribbon-sep" {}
                div class="xl-ribbon-group" {
                    span class="xl-group-label" { "Viền" }
                    div class="xl-row" {
                        button type="button" class="xl-btn" data-xl-border="all" title="Tất cả viền" { "⊞" }
                        button type="button" class="xl-btn" data-xl-border="outer" title="Viền ngoài" { "□" }
                        button type="button" class="xl-btn" data-xl-border="none" title="Bỏ viền" { "✕" }
                    }
                }
                div class="xl-ribbon-sep" {}
                div class="xl-ribbon-group" {
                    span class="xl-group-label" { "Chỉnh sửa" }
                    div class="xl-row" {
                        button type="button" class="xl-btn" data-xl-sort-asc="true" title="Sắp xếp tăng dần" { "↑A" }
                        button type="button" class="xl-btn" data-xl-sort-desc="true" title="Sắp xếp giảm dần" { "↓Z" }
                        button type="button" class="xl-btn" data-xl-clear="true" title="Xóa nội dung ô" { "⌫" }
                    }
                }
            }
            // Sheet area
            div class="xl-sheet-shell" {
                div class="xl-sheet-scroll" {
                    table class="xl-sheet" data-profile-doc-grid="true" {}
                }
                @if can_edit_leaf {
                    form
                        method="post"
                        action=(initial_save_action)
                        class="profile-document-save-form"
                        data-offline-mode="queue"
                        data-requires-online="true"
                        data-profile-doc-save-form="true"
                    {
                        input type="hidden" name="csrf" value=(csrf);
                        textarea name="preview_text" class="visually-hidden" data-profile-doc-payload="true" {}
                    }
                }
            }
            script type="application/json" data-profile-doc-records="true" { (PreEscaped(records_json)) }
        }
    }
}

fn render_document_manager_page(
    user: &User,
    branch_documents: &[Document],
    unit_documents: &[Document],
    selected_document: Option<&Document>,
) -> Markup {
    html! {
        (DOCTYPE)
        html {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { "Quản lý tài liệu" }
                link rel="icon" type="image/svg+xml" href="/assets/emblem.svg";
                link rel="stylesheet" href=(static_assets().base_css_url);
                script src=(static_assets().sync_js_url) defer {}
                script src=(static_assets().dashboard_js_url) defer {}
            }
            body data-panel-root="document-manager" data-sync-username=(&user.username) {
                main class="shell profile-shell" {
                    div class="profile-corners" {
                        div class="left-rail" {
                            button type="button" class="rail-button rail-back" title="Quay lại" data-go-back="true" { "↶" }
                        }
                        a href="/" class="rail-button" title="Về trang chủ" { "⌂" }
                    }
                    section class="card document-manager-page" {
                        div class="sheet-head" {
                            div {
                                h1 { "Quản lý tài liệu" }
                                p class="sheet-subtitle compact-qc-line" { "Danh sách nhánh, danh sách nội bộ và xem nhanh" }
                            }
                        }
                        div class="document-tabs" data-tab-root="doc-page" {
                            div class="tab-strip" {
                                button type="button" class="tab-chip is-active" data-tab-target="branch" { "Nhánh" }
                                button type="button" class="tab-chip" data-tab-target="unit" { "Đơn vị" }
                            }
                            div class="document-manager-layout" {
                                div {
                                    div class="tab-panel is-active" data-tab-panel="branch" { (render_document_list(branch_documents, "", "/documents/manage")) }
                                    div class="tab-panel" data-tab-panel="unit" { (render_document_list(unit_documents, "", "/documents/manage")) }
                                }
                                @if let Some(document) = selected_document {
                                    (render_quick_document_preview(document, None))
                                } @else {
                                    div class="quick-preview-card empty-preview" {
                                        div class="quick-preview-body" tabindex="0" {
                                            p class="muted" { "Chọn tài liệu để xem nhanh." }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn render_login(
    show_error_flash: bool,
    status_message: Option<&str>,
    wait_state: Option<LoginWaitState>,
) -> Markup {
    let wait_message = wait_state
        .as_ref()
        .map(|item| format_login_wait_countdown(item.blocked_until_epoch_ms));
    let unlock_at = wait_state
        .as_ref()
        .map(|item| item.blocked_until_epoch_ms.to_string())
        .unwrap_or_default();
    html! {
        (DOCTYPE)
        html {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { "Đăng nhập hệ thống nội bộ" }
                link rel="icon" type="image/svg+xml" href="/assets/emblem.svg";
                link rel="stylesheet" href=(static_assets().base_css_url);
                script src=(static_assets().sync_js_url) defer {}
                script src=(static_assets().login_js_url) defer {}
            }
            body data-panel-root="login" {
                img class="site-top-banner" src="/assets/site-bg.png" alt="Quân khu 5";
                main class="login-shell" {
                    article class={(if show_error_flash { "card login-card compact-login login-error-flash" } else { "card login-card compact-login" })} {
                        @if let Some(message) = wait_message.as_deref().or(status_message) {
                            p class="login-wait-message" data-login-wait-message="true" { (message) }
                        }
                        form method="post" action="/login" class="stack login-form-minimal" {
                            div class="login-field" {
                                input type="text" name="username" autocomplete="username" aria-label="Tên đăng nhập" required;
                            }
                            div class="login-field" {
                                input type="password" name="password" autocomplete="current-password" aria-label="Mật khẩu" required;
                            }
                            @if wait_state.is_some() {
                                button
                                    type="submit"
                                    class="login-submit"
                                    aria-label="Đăng nhập"
                                    data-login-submit="true"
                                    data-login-unlock-at=(unlock_at)
                                    disabled
                                {
                                    svg class="login-submit-icon" viewBox="0 0 64 64" aria-hidden="true" focusable="false" {
                                        path class="login-submit-arrow-shaft" d="M14 32H38" {}
                                        path class="login-submit-arrow-head" d="M30 24L40 32L30 40" {}
                                        path class="login-submit-bracket" d="M44 14H53V50H44" {}
                                    }
                                }
                            } @else {
                                button
                                    type="submit"
                                    class="login-submit"
                                    aria-label="Đăng nhập"
                                    data-login-submit="true"
                                    data-login-unlock-at=(unlock_at)
                                {
                                    svg class="login-submit-icon" viewBox="0 0 64 64" aria-hidden="true" focusable="false" {
                                        path class="login-submit-arrow-shaft" d="M14 32H38" {}
                                        path class="login-submit-arrow-head" d="M30 24L40 32L30 40" {}
                                        path class="login-submit-bracket" d="M44 14H53V50H44" {}
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

async fn current_user(state: &AppState, jar: &CookieJar) -> Option<User> {
    let session = current_session(state, jar).await?;
    let data = state.data.read().await;
    data.users
        .iter()
        .find(|user| user.id == session.user_id)
        .cloned()
}

async fn current_session(state: &AppState, jar: &CookieJar) -> Option<SessionState> {
    let session_cookie = jar.get("session_id")?;
    state
        .sessions
        .read()
        .await
        .get(session_cookie.value())
        .cloned()
}

async fn require_session(state: &AppState, jar: &CookieJar) -> Option<(User, SessionState)> {
    let session = current_session(state, jar).await?;
    let data = state.data.read().await;
    let user = data
        .users
        .iter()
        .find(|user| user.id == session.user_id)?
        .clone();
    Some((user, session))
}

fn validate_csrf(session: &SessionState, received: &str) -> Result<(), &'static str> {
    if session.csrf_token == received {
        Ok(())
    } else {
        Err("Yêu cầu không hợp lệ, vui lòng đăng nhập lại.")
    }
}

fn visible_org_ids(user: &User, data: &AppData) -> HashSet<String> {
    match user.role {
        UserRole::RootAdmin => data
            .organizations
            .iter()
            .map(|org| org.id.clone())
            .collect(),
        _ => user
            .org_id
            .as_ref()
            .map(|org_id| descendant_ids(&data.organizations, org_id))
            .unwrap_or_default(),
    }
}

fn can_manage_org(user: &User, org_id: &str, data: &AppData) -> bool {
    matches!(user.role, UserRole::RootAdmin | UserRole::OrgManager)
        && visible_org_ids(user, data).contains(org_id)
}

fn can_manage_tree(
    user: &User,
    org_id: &str,
    data: &AppData,
    expected_key: &str,
    provided_key: &str,
) -> bool {
    provided_key == expected_key && visible_org_ids(user, data).contains(org_id)
}

fn persist(state: &AppState, data: &AppData) -> anyhow::Result<()> {
    state.storage.save(data)
}

async fn active_login_wait_state(state: &AppState, username_key: &str) -> Option<LoginWaitState> {
    let attempts = state.login_attempts.read().await;
    let attempt = attempts.get(username_key)?;
    let blocked_until = attempt.blocked_until?;
    if blocked_until > Utc::now() {
        login_wait_label(attempt.failures).map(|_| LoginWaitState {
            blocked_until_epoch_ms: blocked_until.timestamp_millis(),
        })
    } else {
        None
    }
}

async fn register_login_failure(state: &AppState, username_key: &str) -> Option<LoginWaitState> {
    let mut attempts = state.login_attempts.write().await;
    let attempt = attempts
        .entry(username_key.to_owned())
        .or_insert(LoginAttemptState {
            failures: 0,
            blocked_until: None,
        });
    attempt.failures += 1;
    attempt.blocked_until =
        login_block_duration(attempt.failures).map(|duration| Utc::now() + duration);
    match (login_wait_label(attempt.failures), attempt.blocked_until) {
        (Some(_), Some(blocked_until)) => Some(LoginWaitState {
            blocked_until_epoch_ms: blocked_until.timestamp_millis(),
        }),
        _ => None,
    }
}

fn login_block_duration(failures: u32) -> Option<Duration> {
    match failures {
        3 => Some(Duration::minutes(1)),
        4 => Some(Duration::minutes(3)),
        5 => Some(Duration::minutes(5)),
        6 => Some(Duration::minutes(10)),
        7 => Some(Duration::minutes(30)),
        8 => Some(Duration::hours(1)),
        9.. => Some(Duration::hours(24)),
        _ => None,
    }
}

fn login_wait_label(failures: u32) -> Option<&'static str> {
    match failures {
        3 => Some("Chờ 1 phút"),
        4 => Some("Chờ 3 phút"),
        5 => Some("Chờ 5 phút"),
        6 => Some("Chờ 10 phút"),
        7 => Some("Chờ 30 phút"),
        8 => Some("Chờ 1h"),
        9.. => Some("Chờ 24h"),
        _ => None,
    }
}

fn format_login_wait_countdown(blocked_until_epoch_ms: i64) -> String {
    let remaining_ms = (blocked_until_epoch_ms - Utc::now().timestamp_millis()).max(0);
    let total_seconds = (remaining_ms + 999) / 1000;
    let minutes = total_seconds / 60;
    let seconds = total_seconds % 60;
    format!("{}:{:02}", minutes, seconds)
}

fn internal_error(message: &str) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Html(format!("<h1>Loi</h1><p>{}</p>", message)),
    )
        .into_response()
}

fn sanitize_filename(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn base_styles() -> &'static str {
    r#"
        :root {
            color-scheme: light dark;
            --bg: #081018;
            --bg-soft: #0f1722;
            --paper: rgba(13, 22, 34, 0.88);
            --paper-strong: rgba(10, 17, 28, 0.96);
            --ink: #ecf6ff;
            --muted: #8ba0b8;
            --accent: #3dd9c5;
            --accent-deep: #8ff7ea;
            --accent-soft: rgba(61, 217, 197, 0.14);
            --warning: #ffb25b;
            --line: rgba(143, 247, 234, 0.14);
            --shadow: 0 28px 70px rgba(0, 0, 0, 0.38);
        }
        * { box-sizing: border-box; }
        body {
            margin: 0;
            color: var(--ink);
            background:
                radial-gradient(circle at 18% 18%, rgba(61, 217, 197, 0.16), transparent 18%),
                radial-gradient(circle at 82% 14%, rgba(82, 145, 255, 0.16), transparent 16%),
                radial-gradient(circle at 50% 100%, rgba(110, 64, 255, 0.10), transparent 26%),
                linear-gradient(180deg, #07111a 0%, var(--bg) 46%, #050b12 100%);
            font-family: Bahnschrift, "Segoe UI Variable Text", "Trebuchet MS", sans-serif;
        }
        .shell, .login-shell {
            max-width: 1580px;
            margin: 0 auto;
            padding: 28px;
        }
        .command-shell { max-width: 100%; padding: 14px; }
        .login-shell {
            min-height: 100vh;
            display: grid;
            place-items: center;
        }
        body[data-panel-root="login"] {
            background: #f6f7f9 !important;
            color: #111111;
        }
        /* Banner ảnh nền trên cùng: bo góc, canh giữa, vừa vặn */
        .site-top-banner {
            display: block;
            height: auto;
            max-width: 100%;
            margin: 0 auto;
            border-radius: 16px;
        }
        /* Login: banner nhỏ ~2/3, canh giữa */
        body[data-panel-root="login"] .site-top-banner {
            width: 66%;
            max-width: 620px;
            margin: 30px auto 0;
        }
        body[data-panel-root="login"] .login-shell {
            min-height: auto;
            padding-top: 28px;
        }
        .card, .sub-card {
            background: var(--paper);
            border: 1px solid var(--line);
            border-radius: 24px;
            padding: 22px;
            box-shadow: var(--shadow);
            backdrop-filter: blur(18px);
        }
        .sub-card { margin-top: 16px; }
        .graph-stage {
            position: relative;
            min-height: calc(100vh - 36px);
            border-radius: 32px;
            overflow: hidden;
            border: 1px solid #e5e7eb;
            background: #ffffff;
            box-shadow: 0 14px 30px rgba(17, 24, 39, 0.08);
        }
        /* Banner ảnh nền đầu dashboard: nhỏ ~1/2, canh giữa, rõ ràng */
        .dashboard-top-banner {
            width: 50%;
            max-width: 560px;
            margin: 2px auto 12px;
            box-shadow: 0 6px 16px rgba(17, 24, 39, 0.08);
        }
        .minimal-stage { min-height: calc(100vh - 240px); }
        .floating-controls {
            position: absolute;
            top: 18px;
            right: 18px;
            z-index: 6;
            display: grid;
            gap: 12px;
            justify-items: end;
        }
        .top-control-row {
            display: flex;
            gap: 12px;
            align-items: start;
        }
        .control-action-stack {
            display: grid;
            gap: 12px;
            justify-items: end;
            margin-top: 12px;
        }
        .panel-shell {
            position: relative;
        }
        .compact-panel {
            position: absolute;
            top: calc(100% + 10px);
            right: 0;
            display: none !important;
            width: min(320px, calc(100vw - 40px));
            padding: 12px 14px;
            background: #ffffff;
            border-radius: 20px;
            border: 1px solid #d1d5db;
            color: #111111;
            box-shadow: 0 18px 38px rgba(17, 24, 39, 0.16);
            backdrop-filter: blur(18px);
            z-index: 8;
        }
        .panel-shell[data-panel="settings"] > .compact-panel {
            width: min(188px, calc(100vw - 40px));
            padding: 10px;
            border-radius: 14px;
            border: 1px solid #d1d5db;
            box-shadow: 0 12px 24px rgba(17, 24, 39, 0.14);
        }
        .settings-password-wrap {
            display: grid;
            gap: 8px;
            justify-items: stretch;
            width: 100%;
        }
        .settings-action-button {
            background: #ffffff;
            border: 2px solid #111111;
            border-radius: 8px;
            color: #111111;
            width: 100%;
            min-width: 156px;
            min-height: 34px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            padding: 6px 12px;
            cursor: pointer;
            transition: all 0.2s ease;
            white-space: nowrap;
        }
        .settings-action-button svg {
            width: 18px;
            height: 18px;
            display: block;
        }
        .settings-action-button:hover {
            background: #111111;
            border-color: #111111;
            color: #ffffff;
        }
        .settings-password-panel {
            display: grid;
            gap: 8px;
            width: 100%;
        }
        .settings-password-panel[hidden] {
            display: none !important;
        }
        .settings-password-input {
            width: 100%;
            min-height: 34px;
            border-radius: 8px;
            border: 1px solid #d1d5db;
            background: #ffffff;
            color: #111111;
            padding: 8px 10px;
            outline: none;
            box-shadow: none;
        }
        .settings-password-input::placeholder {
            color: #6b7280;
        }
        .settings-password-input:focus {
            border-color: #111111;
        }
        .settings-password-save {
            background: #111111;
            border: 1px solid #111111;
            border-radius: 8px;
            color: #ffffff;
            min-height: 34px;
            cursor: pointer;
            width: 100%;
        }
        .settings-password-save:hover {
            background: #ffffff;
            border-color: #111111;
            color: #111111;
        }
        .settings-password-save:disabled {
            opacity: 0.6;
            cursor: wait;
        }
        .offline-toast {
            position: fixed;
            left: 50%;
            bottom: 22px;
            transform: translate(-50%, 18px);
            padding: 10px 18px;
            border-radius: 999px;
            border: 1px solid rgba(255, 196, 128, 0.42);
            background: rgba(29, 16, 8, 0.94);
            color: #ffe2b8;
            font-size: 0.84rem;
            letter-spacing: 0.02em;
            box-shadow: 0 16px 38px rgba(0, 0, 0, 0.3);
            opacity: 0;
            pointer-events: none;
            transition: opacity 0.18s ease, transform 0.18s ease;
            z-index: 90;
        }
        .offline-toast.is-visible {
            opacity: 1;
            transform: translate(-50%, 0);
        }
        .offline-toast.is-success {
            border-color: rgba(121, 232, 215, 0.4);
            background: rgba(7, 34, 30, 0.94);
            color: #bff8ef;
        }
        .offline-toast.is-error {
            border-color: rgba(255, 145, 145, 0.34);
            background: rgba(38, 10, 12, 0.94);
            color: #ffd0d0;
        }
        .compact-account-panel {
            width: min(116px, calc(100vw - 40px));
            padding: 6px;
            gap: 6px;
            border-radius: 10px;
            border: 0 !important;
            background: transparent !important;
            box-shadow: none !important;
        }
        .panel-shell[data-panel="user"] > .compact-panel {
            top: calc(100% - 30px);
            right: 17px;
            left: auto;
            transform: none;
            justify-items: end;
        }
        .tree-edit-mode-btn,
        .lan-mode-button {
            background: rgba(143, 247, 234, 0.1);
            border: 1px solid rgba(143, 247, 234, 0.2);
            border-radius: 6px;
            color: rgba(143, 247, 234, 0.6);
            width: auto;
            flex: 0 0 auto;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            padding: 6px 12px;
            min-width: 0;
            height: 30px;
            font-weight: 600;
            font-size: 0.85rem;
            cursor: pointer;
            transition: all 0.3s;
        }
        .tree-edit-mode-btn {
            width: auto;
            height: 30px;
            flex: 0 0 auto;
            min-width: 136px;
            padding: 6px 12px;
            color: rgba(255, 255, 255, 0.92);
        }
        .tree-edit-mode-btn svg,
        .tree-edit-sidebar-btn svg,
        .tree-node-editor-btn svg {
            width: 16px;
            height: 16px;
            fill: currentColor;
            display: block;
        }
        .tree-node-editor-btn.user svg {
            width: 20px;
            height: 20px;
            min-width: 20px;
            flex: 0 0 20px;
            overflow: visible;
        }
        .lan-mode-toggle {
            position: relative;
            display: flex;
            align-items: center;
            width: 136px;
            gap: 4px;
        }
        .lan-mode-toggle .lan-mode-button {
            width: 100%;
            min-width: 136px;
            flex: 1 1 136px;
        }
        .lan-mode-toggle .lan-mode-button[data-is-lan="true"] {
            min-width: 0;
            flex-basis: 98px;
        }
        .lan-mode-button[data-is-lan="true"] {
            background: rgba(115, 255, 232, 0.42);
            border-color: rgba(177, 255, 242, 0.74);
            color: #023838;
            box-shadow: 0 0 10px rgba(101, 255, 228, 0.34), 0 0 18px rgba(101, 255, 228, 0.2);
        }
        .lan-mode-button:hover,
        .tree-edit-mode-btn:hover {
            background: rgba(61, 217, 197, 0.2);
            border-color: rgba(61, 217, 197, 0.4);
            color: var(--accent-deep);
        }
        .tree-edit-mode-btn[data-editing="true"] {
            background: rgba(115, 255, 232, 0.42);
            border-color: rgba(177, 255, 242, 0.74);
            color: #023838;
            box-shadow: 0 0 10px rgba(101, 255, 228, 0.34), 0 0 18px rgba(101, 255, 228, 0.2);
        }
        .tree-edit-mode-btn[data-editing="true"]:hover {
            background: rgba(115, 255, 232, 0.42);
            border-color: rgba(177, 255, 242, 0.74);
            color: #023838;
            box-shadow: 0 0 10px rgba(101, 255, 228, 0.34), 0 0 18px rgba(101, 255, 228, 0.2);
        }
        .lan-edit-btn {
            background: rgba(143, 247, 234, 0.1);
            border: 1px solid rgba(143, 247, 234, 0.2);
            border-radius: 6px;
            color: rgba(143, 247, 234, 0.5);
            width: 34px;
            height: 30px;
            flex: 0 0 34px;
            padding: 0;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            transition: all 0.3s;
        }
        .lan-edit-btn[hidden] { display: none !important; }
        .lan-edit-btn:hover {
            background: rgba(143, 247, 234, 0.15);
            color: var(--accent-deep);
        }
        .lan-edit-btn svg {
            width: 18px;
            height: 18px;
            display: block;
            fill: currentColor;
        }
        .ip-whitelist-section {
            position: absolute;
            right: 0;
            top: calc(100% + 8px);
            z-index: 12;
            display: none;
            flex-direction: column;
            gap: 6px;
            width: min(176px, calc(100vw - 40px));
            padding: 8px;
            border-radius: 10px;
            background: rgba(9, 17, 28, 0.96);
            border: 1px solid rgba(143, 247, 234, 0.2);
            box-shadow: 0 14px 28px rgba(0, 0, 0, 0.34);
            backdrop-filter: blur(16px);
            max-height: 172px;
            overflow-y: auto;
            scrollbar-width: thin;
        }
        .ip-whitelist-section.is-open {
            display: flex;
        }
        .ip-list {
            display: flex;
            flex-direction: column;
            gap: 4px;
            max-height: 102px;
            overflow-y: auto;
            scrollbar-width: none;
            -ms-overflow-style: none;
        }
        .ip-list::-webkit-scrollbar { display: none; width: 0; height: 0; }
        .ip-row {
            display: flex;
            align-items: center;
            gap: 4px;
            padding: 4px;
            background: rgba(6, 16, 28, 0.8);
            border: 1px solid rgba(143, 247, 234, 0.15);
            border-radius: 6px;
        }
        .ip-row-input {
            flex: 1;
            min-width: 0;
            border: none;
            background: transparent;
            color: var(--accent-deep);
            font-family: monospace;
            font-size: 0.78rem;
            padding: 2px 4px;
            outline: none;
        }
        .remove-ip-btn {
            background: none;
            border: none;
            color: rgba(255, 100, 100, 0.7);
            cursor: pointer;
            font-size: 0.9rem;
            width: 18px;
            height: 18px;
            padding: 0;
            line-height: 1;
        }
        .remove-ip-btn:hover { color: rgba(255, 100, 100, 1); }
        .ip-add-row-btn {
            align-self: flex-end;
            width: 28px;
            height: 28px;
            background: rgba(61, 217, 197, 0.2);
            border: 1px solid rgba(61, 217, 197, 0.4);
            border-radius: 6px;
            color: var(--accent-deep);
            cursor: pointer;
            font-weight: 600;
            font-size: 1rem;
            line-height: 1;
            padding: 0;
        }
        .ip-add-row-btn:hover { background: rgba(61, 217, 197, 0.3); }
        .account-logout-form {
            margin: 0;
            width: auto;
        }
        .logout-icon-btn {
            width: auto;
            min-width: 108px;
            min-height: 36px;
            border-radius: 8px;
            border: 2px solid #111111 !important;
            outline: 0 !important;
            box-shadow: none !important;
            background: #ffffff !important;
            color: #111111 !important;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            text-align: center;
            padding: 8px 12px;
            line-height: 1;
            font-size: 0.84rem;
            font-weight: 800;
            white-space: nowrap;
        }
        .account-logout-form .logout-icon-btn,
        .compact-account-panel .logout-icon-btn,
        .panel-shell[data-panel="user"] .logout-icon-btn {
            border: 2px solid #111111 !important;
            outline: 0 !important;
            box-shadow: none !important;
            background: #ffffff !important;
            color: #111111 !important;
        }
        .tree-edit-sidebar {
            position: fixed;
            top: auto;
            bottom: 22px;
            left: 50%;
            right: auto;
            transform: translateX(-50%);
            display: flex;
            align-items: center;
            gap: 6px;
            z-index: 40;
            padding: 8px 10px;
            border: 1px solid rgba(17, 17, 17, 0.16);
            border-radius: 9px;
            background: #ffffff;
            box-shadow: 0 10px 24px rgba(17, 24, 39, 0.10);
        }
        .tree-edit-sidebar[hidden] { display: none !important; }
        .tree-edit-sidebar-close {
            position: absolute;
            top: -9px;
            right: -9px;
            width: 20px;
            height: 20px;
            min-width: 20px;
            padding: 0;
            border-radius: 999px;
            border: 1px solid rgba(17, 17, 17, 0.20);
            background: #ffffff;
            color: #111111;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            font-size: 0.86rem;
            font-weight: 800;
            line-height: 1;
            cursor: pointer;
            box-shadow: 0 4px 10px rgba(17, 24, 39, 0.12);
        }
        .tree-edit-sidebar-close:hover {
            background: #f3f4f6;
            color: #111111;
        }
        .tree-edit-sidebar-btn {
            width: 32px;
            height: 32px;
            min-width: 32px;
            padding: 0;
            border-radius: 7px;
            border: 1px solid rgba(17, 17, 17, 0.16);
            background: #ffffff;
            color: #111111;
            box-shadow: none;
            cursor: pointer;
            font-size: 1.05rem;
            line-height: 1;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            text-align: center;
        }
        .tree-edit-sidebar-btn:hover {
            background: #f3f4f6;
            border-color: rgba(17, 17, 17, 0.24);
            color: #111111;
        }
        .tree-edit-sidebar-btn:disabled {
            opacity: 0.45;
            cursor: default;
            box-shadow: none;
            background: #ffffff;
            color: #111111;
        }
        .tree-user-card {
            position: absolute;
            z-index: 21;
            min-width: 184px;
            display: grid;
            gap: 8px;
            padding: 10px;
            border-radius: 12px;
            border: 1px solid rgba(143, 247, 234, 0.22);
            background: rgba(6, 16, 28, 0.95);
            box-shadow: 0 16px 32px rgba(0, 0, 0, 0.34);
            backdrop-filter: blur(10px);
            transform: translate(-50%, 0);
        }
        .tree-user-card[hidden] { display: none !important; }
        .tree-rename-card {
            position: absolute;
            z-index: 22;
            min-width: 220px;
            padding: 8px;
            border-radius: 12px;
            border: 1px solid rgba(143, 247, 234, 0.22);
            background: rgba(6, 16, 28, 0.97);
            box-shadow: 0 16px 32px rgba(0, 0, 0, 0.34);
            backdrop-filter: blur(10px);
            transform: translate(-50%, 0);
        }
        .tree-rename-card[hidden] { display: none !important; }
        .tree-rename-row {
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .tree-rename-input {
            min-width: 0;
            flex: 1;
        }
        .tree-rename-save {
            width: 34px;
            height: 32px;
            flex: 0 0 34px;
            padding: 0;
            border-radius: 8px;
            border: 1px solid rgba(143, 247, 234, 0.28);
            background: rgba(61, 217, 197, 0.16);
            color: var(--accent-deep);
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
        }
        .tree-rename-save:hover {
            background: rgba(61, 217, 197, 0.26);
            border-color: rgba(143, 247, 234, 0.42);
        }
        .tree-rename-save svg {
            width: 16px;
            height: 16px;
            fill: currentColor;
            display: block;
        }
        .tree-user-input {
            height: 32px;
            border-radius: 6px;
            border: 1px solid rgba(143, 247, 234, 0.22);
            background: rgba(9, 18, 28, 0.88);
            color: var(--ink);
            padding: 0 10px;
            outline: none;
            font-size: 0.9rem;
        }
        .tree-user-input::placeholder {
            color: rgba(143, 247, 234, 0.5);
        }
        .tree-user-input:focus {
            border-color: rgba(143, 247, 234, 0.44);
            box-shadow: 0 0 0 2px rgba(143, 247, 234, 0.15);
        }
        .logout-icon-btn:hover {
            background: #ffffff;
            border-color: #111111;
            color: #111111;
        }
        @media (max-width: 640px) {
            .ip-whitelist-section {
                right: 0;
                top: calc(100% + 8px);
                width: min(212px, calc(100vw - 40px));
            }
        }
        .overlay-panel {
            position: absolute;
            inset: 88px 22px 22px 22px;
            z-index: 9;
            display: none;
            align-items: start;
            pointer-events: none;
        }
        .overlay-panel.is-open { display: grid; }
        .overlay-card {
            pointer-events: auto;
            background: rgba(8, 15, 24, 0.95);
            border: 1px solid rgba(143, 247, 234, 0.14);
            border-radius: 24px;
            box-shadow: 0 22px 50px rgba(0, 0, 0, 0.34);
            padding: 16px;
            backdrop-filter: blur(18px);
        }
        .large-overlay-panel { justify-items: center; }
        .large-overlay-panel .overlay-card { width: min(920px, calc(100vw - 80px)); }
        .side-overlay-panel { justify-items: start; }
        .overlay-head {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 12px;
            margin-bottom: 12px;
        }
        .profile-right-tools {
            display: flex;
            gap: 10px;
            align-items: start;
            margin-left: auto;
        }
        .profile-corner-button {
            width: 46px;
            height: 46px;
            min-width: 46px;
            padding: 0;
            border: none !important;
            background: transparent !important;
            box-shadow: none !important;
            color: #ffffff !important;
        }
        .profile-corner-button svg {
            width: 24px;
            height: 24px;
            display: block;
        }
        .profile-home-button svg {
            width: 23px;
            height: 23px;
        }
        .profile-home-unit-code {
            display: inline-grid;
            place-items: center;
            width: 100%;
            height: 100%;
            border-radius: 999px;
            background: transparent;
            color: #111111;
            border: 0;
            font-size: 0.78rem;
            font-weight: 800;
            line-height: 1;
            text-transform: none;
            padding: 0 5px;
        }
        .icon-drawer, .message-drawer {
            border-radius: 22px;
            background: rgba(9, 17, 28, 0.82);
            border: 1px solid rgba(143, 247, 234, 0.14);
            box-shadow: 0 16px 38px rgba(0, 0, 0, 0.24);
            overflow: hidden;
            backdrop-filter: blur(18px);
        }
        .icon-drawer > summary, .message-drawer > summary {
            cursor: pointer;
            list-style: none;
            background: transparent;
        }
        .icon-drawer > summary::-webkit-details-marker,
        .message-drawer > summary::-webkit-details-marker,
        .nested-drawer > summary::-webkit-details-marker { display: none; }
        .icon-button, .unit-badge-button {
            width: 40px;
            height: 40px;
            display: inline-grid;
            place-items: center;
            border-radius: 999px;
            border: 1.5px solid rgba(143, 247, 234, 0.38);
            background: rgba(6, 15, 24, 0.86);
            color: var(--ink);
            font-weight: 700;
            font-size: 1.25rem;
            line-height: 1;
            box-shadow: 0 11px 19px rgba(0, 0, 0, 0.22);
        }
        .unit-badge-button {
            min-width: 40px;
            width: auto;
            padding: 0 12px;
            text-transform: lowercase;
        }
        .icon-button.dashboard-control-button {
            width: 32px;
            height: 32px;
            border: none !important;
            border-radius: 0 !important;
            box-shadow: none !important;
            background: transparent !important;
            padding: 0 !important;
            font-size: 1.65rem;
            color: #ffffff !important;
            line-height: 1;
            display: grid !important;
            place-items: center;
        }
        .icon-button.dashboard-control-button svg {
            width: 20px;
            height: 20px;
            display: block;
            fill: currentColor;
        }
        .icon-button.dashboard-control-button.account-control-button {
            width: 62px;
            height: 62px;
            transform: translateY(-13px);
        }
        .icon-button.dashboard-control-button.account-control-button:hover,
        .icon-button.dashboard-control-button.account-control-button:focus-visible,
        .icon-button.dashboard-control-button.account-control-button:active {
            transform: translateY(-13px) !important;
            animation: none !important;
            box-shadow: none !important;
        }
        .icon-button.dashboard-control-button.account-control-button svg {
            width: 28px;
            height: 28px;
        }
        .dashboard-action-button {
            width: 108px;
            height: 38px;
            font-size: 0.88rem;
            line-height: 1;
            border: 1.5px solid #111111 !important;
            border-radius: 8px !important;
            box-shadow: none !important;
            background: #ffffff !important;
            color: #111111 !important;
            text-decoration: none !important;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 7px;
            padding: 0 11px;
            font-weight: 800;
            white-space: nowrap;
        }
        .dashboard-action-button svg {
            width: 17px;
            height: 17px;
            fill: currentColor;
            flex: 0 0 17px;
        }
        .icon-panel {
            display: grid;
            gap: 14px;
            padding: 14px 16px 16px;
            width: min(420px, calc(100vw - 48px));
        }
        .panel-shell[data-panel="settings"] > .icon-panel.compact-panel {
            width: min(236px, calc(100vw - 40px)) !important;
            padding: 8px 10px !important;
            border-radius: 14px;
            border: 1px solid rgba(143, 247, 234, 0.1);
            box-shadow: 0 12px 24px rgba(0, 0, 0, 0.22);
        }
        .panel-shell[data-panel="user"] > .icon-panel.compact-panel {
            width: min(116px, calc(100vw - 40px)) !important;
            padding: 6px !important;
            border-radius: 10px;
            border: 0 !important;
            background: transparent !important;
            box-shadow: none !important;
        }
        .panel-shell > .compact-panel { display: none !important; }
        .panel-shell.is-open > .compact-panel { display: grid !important; }
        .nested-drawer {
            border: 1px solid rgba(143, 247, 234, 0.10);
            border-radius: 18px;
            background: rgba(255,255,255,0.02);
            padding: 10px 12px;
        }
        .nested-drawer > summary {
            cursor: pointer;
            list-style: none;
            font-weight: 700;
            color: var(--ink);
        }
        .compact-tag {
            display: inline-flex;
            align-items: center;
            padding: 7px 12px;
            border-radius: 999px;
            background: rgba(61, 217, 197, 0.08);
            border: 1px solid rgba(61, 217, 197, 0.16);
            color: var(--accent-deep);
            font-size: 0.84rem;
        }
        .graph-card {
            position: relative;
            min-height: calc(100vh - 36px);
            padding: 52px 24px 24px;
            background: transparent;
            border: 0;
            box-shadow: none;
        }
        .graph-grid, .graph-aura {
            position: absolute;
            inset: 0;
            pointer-events: none;
        }
        .graph-grid {
            background-image:
                linear-gradient(rgba(143, 247, 234, 0.06) 1px, transparent 1px),
                linear-gradient(90deg, rgba(143, 247, 234, 0.06) 1px, transparent 1px);
            background-size: 40px 40px;
            mask-image: radial-gradient(circle at center, black 46%, transparent 92%);
        }
        .graph-aura-left {
            background: radial-gradient(circle at 20% 30%, rgba(61,217,197,0.16), transparent 28%);
        }
        .graph-aura-right {
            background: radial-gradient(circle at 78% 20%, rgba(82,145,255,0.14), transparent 24%);
        }
        .pill {
            display: inline-flex;
            align-items: center;
            padding: 8px 12px;
            border-radius: 999px;
            background: rgba(255,255,255,0.14);
            border: 1px solid rgba(255,255,255,0.2);
        }
        .eyebrow { text-transform: uppercase; letter-spacing: 0.16em; font-size: 0.76rem; opacity: 0.84; }
        .muted-eyebrow { color: var(--muted); opacity: 1; }
        .muted { color: var(--muted); }
        .details { display: grid; grid-template-columns: 1fr 2fr; gap: 10px 14px; }
        .tree-canvas {
            position: relative;
            padding: 12px 72px 12px 12px;
            border-radius: 28px;
            background: linear-gradient(180deg, rgba(7, 13, 21, 0.66), rgba(7, 13, 21, 0.18));
            border: 1px solid rgba(143, 247, 234, 0.10);
            min-height: calc(100vh - 116px);
            display: grid;
            align-items: center;
        }
        .tree-viewport {
            width: 100%;
            min-height: calc(100vh - 104px);
            touch-action: none;
            cursor: grab;
            display: grid;
            place-items: center;
        }
        .tree-viewport.dragging { cursor: grabbing; }
        .tree-viewport.edit-mode { cursor: default; }
        .tree-viewport.edit-mode .tree-node-group { cursor: move; }
        .tree-node-editor {
            position: absolute;
            z-index: 20;
            display: grid;
            gap: 6px;
            padding: 7px;
            border-radius: 12px;
            border: 1px solid rgba(143, 247, 234, 0.24);
            background: rgba(6, 16, 28, 0.94);
            box-shadow: 0 12px 26px rgba(0, 0, 0, 0.36);
            backdrop-filter: blur(10px);
            transform: translate(-50%, 0);
        }
        .tree-node-editor[hidden] { display: none !important; }
        .tree-node-editor-btn {
            width: 34px;
            height: 34px;
            border-radius: 8px;
            border: 1px solid rgba(143, 247, 234, 0.28);
            background: rgba(143, 247, 234, 0.08);
            color: rgba(143, 247, 234, 0.9);
            display: inline-flex;
            align-items: center;
            justify-content: center;
            font-size: 1rem;
            line-height: 1;
            cursor: pointer;
        }
        .tree-node-editor-btn:hover {
            background: rgba(143, 247, 234, 0.17);
            border-color: rgba(143, 247, 234, 0.44);
        }
        .tree-node-editor-btn.user {
            color: rgba(255, 255, 255, 0.92);
        }
        .tree-node-editor-btn.delete:hover {
            border-color: rgba(255, 117, 117, 0.55);
            color: #ff8d8d;
            background: rgba(255, 117, 117, 0.14);
        }
        .tree-edit-edge {
            stroke: rgba(143, 247, 234, 0.34);
            stroke-width: 1.8;
        }
        .org-svg {
            width: 100%;
            height: min(calc(100vh - 88px), 1260px);
            display: block;
        }
        .tree-edge { stroke: rgba(143, 247, 234, 0.24); stroke-width: 1.7; pointer-events: none; }
        .tree-edge.highlighted {
            stroke: rgba(145, 255, 212, 0.94);
            stroke-width: 3.2;
            filter: drop-shadow(0 0 12px rgba(145, 255, 212, 0.33));
        }
        .d-cluster, .tree-node-group {
            transition: filter 140ms ease, opacity 140ms ease, stroke 140ms ease;
            transform-box: fill-box;
            transform-origin: center;
        }
        .tree-node-link, .tree-node-link * { pointer-events: all; }
        .tree-node {
            fill: #ffffff;
            stroke: #111111;
            stroke-width: 2.2;
            filter: drop-shadow(0 6px 12px rgba(17, 24, 39, 0.14));
        }
        .tree-node.highlighted {
            fill: #ffffff;
            stroke: #111111;
            stroke-width: 3;
            filter: drop-shadow(0 8px 16px rgba(17, 24, 39, 0.18));
        }
        .tree-node.current.highlighted {
            fill: #ffffff;
            stroke: #111111;
        }
        .tree-node-link:hover .tree-node,
        .tree-node-link:focus-visible .tree-node {
            stroke: #111111;
            stroke-width: 3;
            filter: drop-shadow(0 8px 18px rgba(17, 24, 39, 0.22));
        }
        .tree-node.current { fill: #ffffff; stroke: #111111; stroke-width: 3; }
        .tier-0 .tree-node,
        .tier-1 .tree-node,
        .tier-2 .tree-node,
        .tier-3 .tree-node { fill: #ffffff; stroke: #111111; stroke-width: 2.2; }
        .generation-0 .tree-node { stroke: #dc2626; }
        .generation-1 .tree-node { stroke: #2563eb; }
        .generation-2 .tree-node { stroke: #0ea5e9; }
        .tier-0 .tree-node.highlighted,
        .tier-1 .tree-node.highlighted,
        .tier-2 .tree-node.highlighted,
        .tier-3 .tree-node.highlighted {
            fill: #ffffff;
            stroke-width: 3;
            filter: drop-shadow(0 8px 16px rgba(17, 24, 39, 0.18));
        }
        .tier-0 .tree-node.current.highlighted,
        .tier-1 .tree-node.current.highlighted,
        .tier-2 .tree-node.current.highlighted,
        .tier-3 .tree-node.current.highlighted {
            fill: #ffffff;
        }
        .tier-0 .tree-node-text { font-size: 28px; }
        .tier-1 .tree-node-text { font-size: 22px; }
        .tier-2 .tree-node-text { font-size: 17px; }
        .tier-3 .tree-node-text { font-size: 14px; }
        .tree-node-text { font-weight: 800; fill: #111111; pointer-events: none; letter-spacing: 0; }
        .command-shell { background: #ffffff; color: #111111; }
        .command-shell .icon-button.dashboard-control-button { color: #111111 !important; }
        .command-shell .dashboard-action-button {
            width: 108px;
            height: 38px;
            border: 1.5px solid #111111 !important;
            border-radius: 8px !important;
            background: #ffffff !important;
            color: #111111 !important;
            box-shadow: none !important;
            font-size: 0.88rem;
            font-weight: 800;
            white-space: nowrap;
            text-decoration: none !important;
        }
        .command-shell .dashboard-action-button:hover,
        .command-shell .dashboard-action-button:focus-visible { background: #111111 !important; color: #ffffff !important; }
        .command-shell .compact-panel { background: #ffffff; color: #111111; border-color: #d1d5db; box-shadow: 0 18px 38px rgba(17,24,39,0.16); }
        .command-shell .graph-card-minimal { padding: 0; min-height: calc(100vh - 30px); }
        .command-shell .tree-canvas { background: transparent; border-color: transparent; border-radius: 0; padding: 18px 118px 18px 18px; min-height: calc(100vh - 30px); }
        .command-shell .tree-viewport { min-height: calc(100vh - 66px); }
        .command-shell .panel-shell[data-panel="settings"] > .icon-panel.compact-panel,
        .command-shell .panel-shell[data-panel="settings"] > .compact-panel { width: min(188px, calc(100vw - 40px)) !important; padding: 10px !important; }
        .command-shell .panel-shell[data-panel="user"] > .icon-panel.compact-panel,
        .command-shell .panel-shell[data-panel="user"] > .compact-panel { top: calc(100% - 30px); right: 17px; width: min(116px, calc(100vw - 40px)) !important; padding: 6px !important; border: 0 !important; border-radius: 10px; background: transparent !important; box-shadow: none !important; justify-items: end; }
        .command-shell .logout-icon-btn { background: #ffffff !important; color: #111111 !important; border: 1.5px solid #111111 !important; outline: 0 !important; box-shadow: none !important; }
        .command-shell .logout-icon-btn:hover { background: #111111 !important; color: #ffffff !important; }
        .command-shell .panel-shell[data-panel="docs"] > .compact-panel,
        .command-shell .panel-shell[data-panel="reports"] > .compact-panel { top: calc(100% + 8px); right: 0; width: min(160px, calc(100vw - 40px)) !important; padding: 10px !important; border: 1px solid #d1d5db !important; border-radius: 12px !important; background: #ffffff; }
        .command-shell .settings-action-button { width: 100%; min-width: 156px; background: #ffffff; border: 1.5px solid #111111; color: #111111; }
        .command-shell .settings-action-button:hover { background: #111111; color: #ffffff; }
        .command-shell .lan-mode-toggle { width: 156px; }
        .command-shell .lan-mode-toggle .lan-mode-button { min-width: 156px; height: 30px; background: #ffffff !important; border: 1.5px solid #111111 !important; color: #111111 !important; box-shadow: none !important; }
        .command-shell .lan-mode-toggle .lan-mode-button[data-is-lan="true"] { min-width: 0; flex-basis: 116px; }
        .command-shell .lan-edit-btn { background: #ffffff !important; border: 1.5px solid #111111 !important; color: #111111 !important; box-shadow: none !important; }
        .command-shell .lan-mode-button:hover, .command-shell .lan-edit-btn:hover { background: #111111 !important; color: #ffffff !important; }
        .command-shell .ip-whitelist-section { background: #ffffff; border: 1.5px solid #111111; color: #111111; box-shadow: 0 14px 28px rgba(17,24,39,0.16); }
        .command-shell .ip-row { background: #ffffff; border: 1px solid #d1d5db; }
        .command-shell .ip-row-input { color: #111111; }
        .command-shell .remove-ip-btn { color: #111111; }
        .command-shell .remove-ip-btn:hover { color: #111111; }
        .command-shell .ip-add-row-btn { background: #ffffff; border: 1.5px solid #111111; color: #111111; }
        .command-shell .ip-add-row-btn:hover { background: #111111; color: #ffffff; }
        .command-shell .graph-grid { background-image: linear-gradient(rgba(17,24,39,0.055) 1px, transparent 1px), linear-gradient(90deg, rgba(17,24,39,0.055) 1px, transparent 1px); }
        .command-shell .graph-aura { background: transparent; }
        .command-shell .tree-node-editor { background: #ffffff; border-color: #111111; box-shadow: 0 12px 26px rgba(17,24,39,0.18); }
        .command-shell .tree-node-editor-btn { background: #ffffff; border-color: #111111; color: #111111; }
        .command-shell .tree-node-editor-btn svg { fill: #111111; }
        .command-shell .tree-node-editor-btn:hover { background: #111111; color: #ffffff; }
        .command-shell .tree-node-editor-btn:hover svg { fill: #ffffff; }
        .command-shell .tree-edge { stroke: rgba(17,24,39,0.22); }
        .command-shell .tree-node, .command-shell .tier-0 .tree-node, .command-shell .tier-1 .tree-node, .command-shell .tier-2 .tree-node, .command-shell .tier-3 .tree-node { fill: #ffffff; stroke: #111111; stroke-width: 2.2; }
        .command-shell .generation-0 .tree-node { stroke: #dc2626; }
        .command-shell .generation-1 .tree-node { stroke: #2563eb; }
        .command-shell .generation-2 .tree-node { stroke: #0ea5e9; }
        .command-shell .tree-node.highlighted, .command-shell .tier-0 .tree-node.highlighted, .command-shell .tier-1 .tree-node.highlighted, .command-shell .tier-2 .tree-node.highlighted, .command-shell .tier-3 .tree-node.highlighted { fill: #ffffff; stroke-width: 3; }
        .command-shell .tier-0 .tree-node-text { font-size: 32px; }
        .command-shell .tier-1 .tree-node-text { font-size: 25px; }
        .command-shell .tier-2 .tree-node-text { font-size: 20px; }
        .command-shell .tier-3 .tree-node-text { font-size: 16px; }
        .command-shell .tree-node-text { fill: #111111; letter-spacing: 0; }
        .dashboard-documents-panel { max-height: none; overflow: visible; gap: 7px; padding: 9px; box-shadow: 0 14px 28px rgba(17,24,39,0.16) !important; }
        .dashboard-unit-picker { display: grid; gap: 7px; min-width: 0; font-size: 0.84rem; }
        .dashboard-unit-picker strong { font-size: 0.82rem; color: #111111; }
        .dashboard-unit-search { width: 100%; min-height: 30px; border: 1px solid #d1d5db; border-radius: 7px; background: #ffffff; color: #111111; padding: 5px 8px; outline: none; font-size: 0.78rem; }
        .dashboard-unit-search:focus { border-color: #111111; box-shadow: inset 0 0 0 1px #111111; }
        .dashboard-doc-panel-toolbar { display: grid; grid-template-columns: minmax(0, 1fr) 28px; align-items: center; gap: 6px; }
        .dashboard-doc-upload-link { min-height: 28px; display: flex; align-items: center; justify-content: center; color: #166534; border: 1.5px solid #16a34a; border-radius: 7px; background: #f0fdf4; padding: 5px 8px; font-size: 0.78rem; font-weight: 800; cursor: pointer; box-shadow: inset 0 0 0 1px rgba(22, 163, 74, 0.10); }
        .dashboard-doc-upload-link:hover { color: #ffffff; background: #16a34a; border-color: #15803d; }
        .dashboard-doc-search-icon { display: grid; place-items: center; width: 28px; height: 28px; border: 0; background: transparent; color: #111111; cursor: pointer; font-size: 1rem; padding: 0; }
        .dashboard-doc-search-icon:hover, .dashboard-doc-search-icon.is-active { color: #2563eb; }
        .dashboard-unit-search-collapsed[hidden] { display: none !important; }
        .dashboard-report-panel { max-height: none; overflow: visible; gap: 7px; padding: 9px; box-shadow: 0 14px 28px rgba(17,24,39,0.16) !important; }
        .report-unit-list { display: grid; gap: 5px; margin-top: 6px; max-height: 176px; overflow: auto; }
        .report-unit-row { position: relative; display: grid; grid-template-columns: minmax(0, 1fr) 18px; column-gap: 2px; align-items: center; min-width: 0; }
        .report-unit-item { display: flex; align-items: center; width: 100%; min-height: 28px; border-radius: 7px; border: 1px solid #d1d5db; background: #ffffff; color: #111111; text-align: left; cursor: pointer; padding: 5px 8px; font-size: 0.78rem; font-weight: 800; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .report-unit-more { display: grid; place-items: center; width: 18px; min-width: 18px; min-height: 28px; border: 0; border-radius: 0; background: transparent; color: #111111; cursor: pointer; font-size: 1.05rem; line-height: 1; padding: 0; }
        .report-unit-more:hover { color: #2563eb; background: transparent; }
        .report-unit-action-menu { position: fixed; z-index: 2000; display: grid; gap: 4px; padding: 5px; border: 1px solid #d1d5db; border-radius: 8px; background: #ffffff; box-shadow: 0 12px 24px rgba(17,24,39,0.16); }
        .report-unit-action-menu[hidden] { display: none !important; }
        .report-unit-action { display: grid; place-items: center; width: 28px; height: 28px; border: 1px solid #d1d5db; border-radius: 7px; background: #ffffff; color: #111111; cursor: pointer; padding: 0; font-size: 0.94rem; }
        .report-unit-action:hover { border-color: #111111; background: #111111; color: #ffffff; }
        .report-unit-action-delete:hover { border-color: #dc2626; background: #dc2626; color: #ffffff; }
        .report-unit-item:hover, .report-unit-item.is-active { border-color: #111111; box-shadow: inset 0 0 0 1px #111111; }
        .report-document-workspace { display: grid; gap: 0; width: min(1120px, 100%); margin: 0 auto; }
        .report-tab-bar { border: 1px solid rgba(17, 17, 17, 0.14); border-bottom: 0; border-radius: 8px 8px 0 0; }
        .report-document-tab { max-width: 170px; }
        .report-add-tab-btn { flex: 0 0 auto; }
        .report-tab-actions .xl-action-btn { text-decoration: none; }
        .report-edit-surface { border: 1px solid #e5e7eb; border-radius: 10px; padding: 12px; outline: none; font-family: "Times New Roman", Times, serif; }
        .report-tab-bar + .report-word-ribbon + .report-edit-surface,
        .report-tab-bar + .report-edit-surface { border-radius: 0 0 10px 10px; }
        .report-edit-surface.is-editing { border-color: #111111; box-shadow: inset 0 0 0 1px #111111; }
        .report-document { color: #111111; background: #ffffff; display: grid; gap: 12px; line-height: 1.45; font-family: "Times New Roman", Times, serif; }
        .report-letterhead {
            display: flex;
            align-items: center;
            gap: 16px;
            padding: 6px 4px 14px;
            border-bottom: 2.5px solid #8c1109;
            margin-bottom: 4px;
        }
        .report-letterhead-emblem {
            flex: 0 0 64px;
            width: 64px;
            height: 64px;
            background: url("/assets/emblem.svg") center / contain no-repeat;
        }
        .report-letterhead-text { display: grid; gap: 2px; }
        .report-letterhead-over { font-size: 0.82rem; font-weight: 700; letter-spacing: 2px; color: #8c1109; }
        .report-letterhead-title { margin: 0; font-size: 1.35rem; font-weight: 800; letter-spacing: 1px; color: #111111; }
        .report-letterhead-unit { margin: 0; font-size: 0.92rem; color: #374151; }
        body[data-panel-root="manage"] {
            background:
                radial-gradient(circle at 50% 120%, rgba(205, 162, 58, 0.08), transparent 55%),
                #f4f5f7 !important;
            color: #111111;
        }
        .manage-shell { max-width: 1080px; margin: 0 auto; padding: 22px 18px 60px; }
        .manage-header {
            display: flex; align-items: center; gap: 14px;
            padding: 14px 18px; margin-bottom: 18px;
            background: #ffffff; border-radius: 16px;
            border-left: 5px solid #8c1109;
            box-shadow: 0 8px 22px rgba(17, 24, 39, 0.08);
        }
        .manage-emblem { width: 56px; height: 56px; }
        .manage-header-text { display: grid; gap: 2px; margin-right: auto; }
        .manage-over { font-size: 0.74rem; font-weight: 700; letter-spacing: 2px; color: #8c1109; }
        .manage-title { margin: 0; font-size: 1.3rem; font-weight: 800; color: #111111; }
        .manage-header-actions { display: flex; gap: 8px; }
        .manage-link-btn {
            text-decoration: none; color: #111111; background: #ffffff;
            border: 1.5px solid #111111; border-radius: 8px;
            padding: 7px 14px; font-size: 0.85rem; font-weight: 600; white-space: nowrap;
        }
        .manage-link-btn:hover { background: #111111; color: #ffffff; }
        .manage-card {
            background: #ffffff; border: 1px solid #e5e7eb; border-radius: 16px;
            padding: 18px 20px; margin-bottom: 16px;
            box-shadow: 0 6px 16px rgba(17, 24, 39, 0.05);
        }
        .manage-card h2 { margin: 0 0 12px; font-size: 1.05rem; color: #111111; border-bottom: 1px solid #eef0f3; padding-bottom: 8px; }
        .manage-table-wrap { overflow-x: auto; }
        .manage-table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
        .manage-table th, .manage-table td { text-align: left; padding: 8px 10px; border-bottom: 1px solid #eef0f3; vertical-align: top; }
        .manage-table th { color: #6b7280; font-weight: 700; font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.4px; }
        .manage-list { margin: 0; padding-left: 18px; display: grid; gap: 6px; }
        .manage-list a { color: #1a56d6; font-weight: 600; text-decoration: none; }
        .manage-list a:hover { text-decoration: underline; }
        .manage-add, .manage-edit { margin-top: 12px; }
        .manage-add > summary, .manage-edit > summary {
            cursor: pointer; display: inline-block; font-weight: 700; color: #8c1109;
            padding: 6px 10px; border: 1.5px dashed #8c1109; border-radius: 8px; font-size: 0.85rem;
        }
        .manage-edit > summary { color: #1a56d6; border-color: #b9c6e6; }
        .manage-add[open] > summary, .manage-edit[open] > summary { margin-bottom: 10px; }
        .manage-form-grid {
            display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px 14px;
            background: #fafbfc; border: 1px solid #eef0f3; border-radius: 12px; padding: 14px;
        }
        .manage-form-grid label { display: grid; gap: 4px; font-size: 0.8rem; color: #374151; font-weight: 600; }
        .manage-form-grid input[type=text], .manage-form-grid input[type=number],
        .manage-form-grid input[type=password], .manage-form-grid select {
            border: 1.5px solid #cbd2dc; border-radius: 8px; padding: 8px 10px; font-size: 0.9rem; background: #ffffff; color: #111111;
        }
        .manage-form-grid input:focus, .manage-form-grid select:focus { outline: none; border-color: #8c1109; }
        .manage-span2 { grid-column: 1 / -1; }
        .manage-check { flex-direction: row; align-items: center; display: flex; gap: 8px; font-weight: 600; }
        .manage-check input { width: 16px; height: 16px; }
        .manage-submit {
            grid-column: 1 / -1; justify-self: start;
            background: #8c1109; color: #ffffff; border: 0; border-radius: 8px;
            padding: 9px 18px; font-weight: 700; font-size: 0.88rem; cursor: pointer;
        }
        .manage-submit:hover { background: #a8160d; }
        .manage-submit-sm { padding: 5px 12px; font-size: 0.8rem; }
        .manage-inline-form { margin: 0; }
        .manage-note { margin: 10px 0 0; font-size: 0.82rem; }
        @media (max-width: 640px) { .manage-form-grid { grid-template-columns: 1fr; } }
        .report-word-ribbon {
            display: flex;
            flex-wrap: nowrap;
            align-items: stretch;
            background: #ffffff;
            border: 1px solid rgba(17, 17, 17, 0.14);
            border-bottom: 0;
            color: #111111;
            padding: 7px 8px 6px;
            max-height: 82px;
            overflow-x: auto;
            overflow-y: hidden;
            scrollbar-width: thin;
        }
        .word-ribbon-group { display: flex; flex: 0 0 auto; flex-direction: column; gap: 5px; align-items: flex-start; justify-content: center; padding: 4px 10px 5px; }
        .report-word-ribbon .xl-group-label { color: #111111; }
        .report-word-ribbon .xl-ribbon-sep { background: #111111; opacity: 0.22; }
        .report-word-ribbon .xl-btn { color: #111111; border-color: transparent; }
        .report-word-ribbon .xl-btn:hover,
        .report-word-ribbon .xl-btn.is-active { background: #111111; color: #ffffff; border-color: #111111; }
        .report-word-ribbon .xl-select { background: #ffffff; color: #111111; border-color: rgba(17, 17, 17, 0.18); }
        .report-document dl { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 8px; margin: 0; }
        .report-document dl div { border: 1px solid #e5e7eb; border-radius: 8px; padding: 8px; }
        .report-document dt { color: #4b5563; font-size: 0.78rem; }
        .report-document dd { margin: 2px 0 0; font-weight: 800; }
        .report-chart h4, .report-activities h4 { margin: 0 0 8px; }
        .report-chart-row { display: grid; grid-template-columns: 96px minmax(220px, 0.92fr) minmax(280px, 1.18fr); gap: 14px; align-items: center; }
        .report-pie { width: 92px; height: 92px; border-radius: 999px; border: 1px solid #e5e7eb; flex: 0 0 92px; }
        .report-chart ul { list-style: none; padding: 0; margin: 0; display: grid; gap: 5px; }
        .report-chart li { display: flex; gap: 7px; align-items: center; }
        .report-chart li span { width: 12px; height: 12px; border-radius: 999px; flex: 0 0 12px; }
        .report-chart-analysis { display: grid; gap: 5px; align-self: stretch; align-content: center; padding: 8px 10px; border-left: 1px solid #e5e7eb; color: #111111; }
        .report-chart-analysis p { margin: 0; font-size: 0.92rem; line-height: 1.42; }
        @media (max-width: 820px) {
            .report-chart-row { grid-template-columns: 96px 1fr; }
            .report-chart-analysis { grid-column: 1 / -1; border-left: 0; border-top: 1px solid #e5e7eb; padding-left: 0; }
        }
        .profile-report-surface { background: #ffffff; }
        .tab-link, .text-link, .back-link {
            color: var(--accent-deep);
            text-decoration: none;
            font-weight: 600;
        }
        .back-link, .text-link:hover { text-decoration: underline; }
        html:has(body[data-panel-root="profile"]),
        body[data-panel-root="profile"] { background: #ffffff !important; color: #111111; }
        body[data-panel-root="profile"] { min-width: 0; overflow-x: hidden; }
        .profile-shell { padding-top: 12px; background: #ffffff; min-height: 100vh; width: 100%; max-width: 100vw; color: #111; box-sizing: border-box; overflow-x: hidden; }
        .profile-shell * { --text-primary: #111; --text-muted: #444; }
        .profile-shell .sheet-title, .profile-shell .sheet-label,
        .profile-shell .xl-tab-label, .profile-shell .compact-tag,
        .profile-shell .text-link { color: #1a56d6; }
        .profile-shell .rail-button { background: #ffffff; border-color: #111111; color: #111111; }
        .profile-shell .xl-sheet td, .profile-shell .xl-sheet th { color: #111; border-color: #dde3f0; }
        .profile-shell .xl-sheet { background: #fff; }
        .profile-shell .xl-sheet-shell,
        .profile-shell .xl-sheet-scroll {
            background: #ffffff !important;
            scrollbar-color: #cbd8f4 #ffffff;
        }
        .profile-shell .xl-sheet-shell::-webkit-scrollbar,
        .profile-shell .xl-sheet-scroll::-webkit-scrollbar { width: 12px; height: 12px; }
        .profile-shell .xl-sheet-shell::-webkit-scrollbar-track,
        .profile-shell .xl-sheet-scroll::-webkit-scrollbar-track { background: #ffffff; }
        .profile-shell .xl-sheet-shell::-webkit-scrollbar-thumb,
        .profile-shell .xl-sheet-scroll::-webkit-scrollbar-thumb { background: #cbd8f4; border: 3px solid #ffffff; border-radius: 999px; }
        .profile-shell .xl-sheet-shell::-webkit-scrollbar-corner,
        .profile-shell .xl-sheet-scroll::-webkit-scrollbar-corner { background: #ffffff; }
        .profile-shell .xl-sheet thead th {
            background: #f7fafd !important;
            color: #1a56d6 !important;
            border-color: #cbd8f4 !important;
            border-bottom: 1.5px solid #b3c6f7 !important;
        }
        .profile-shell .xl-sheet tbody td {
            background: #ffffff !important;
            color: #111111 !important;
            border-color: #dde3f0 !important;
        }
        .profile-shell .xl-sheet tbody tr.is-data-header td {
            font-weight: 800;
            color: #111111 !important;
            background: #f8fbff !important;
        }
        .profile-shell .xl-sheet td.xl-unit-activity-cell {
            vertical-align: top;
            white-space: pre-wrap;
            line-height: 1.5;
            background: #ffffff !important;
        }
        .profile-shell .xl-tab-strip { border-bottom: 2px solid #dde3f0; }
        .profile-shell .xl-tab-chip { color: #444; background: #f5f7ff; border-color: #ccd5f0; }
        .profile-shell .xl-tab-chip.is-active { background: #e2e9ff; border-color: #7096f0; color: #1a3fa6; }
        .profile-shell .xl-action-btn { background: #f0f4ff; border-color: #b3c6f7; color: #1a56d6; }
        .profile-shell .compact-panel { background: #fff; border: 1.5px solid #b3c6f7; }
        .profile-shell .profile-document-actions { border-top: 2px solid #dde3f0; }
        /* Profile-shell light theme overrides — make icons visible on white,
           drop the legacy dark tab bar, and harmonize the sheet header. */
        .profile-shell .profile-corner-button {
            color: #111111 !important;
            background: #ffffff !important;
            border: 1.5px solid #111111 !important;
            box-shadow: none !important;
        }
        .profile-shell .profile-corner-button:hover {
            background: #111111 !important;
            color: #ffffff !important;
        }
        .profile-shell .profile-home-button.profile-corner-button {
            background: #ffffff !important;
            color: #111111 !important;
            border: none !important;
            width: 38px !important;
            height: 38px !important;
            min-width: 38px !important;
            box-shadow: none !important;
        }
        .profile-shell .profile-home-button.profile-corner-button svg { width: 26px; height: 26px; display: block; }
        .profile-shell .rail-back.profile-corner-button {
            border: none !important;
            background: transparent !important;
            box-shadow: none !important;
        }
        .profile-shell .rail-back.profile-corner-button:hover {
            border: none !important;
            background: #f3f4f6 !important;
            color: #111111 !important;
        }
        .profile-shell .profile-home-button.profile-corner-button:hover {
            background: #f3f4f6 !important;
            color: #111111 !important;
        }
        .profile-shell .profile-unit-title-code { color: #111111; font-size: 1.55rem; line-height: 1; font-weight: 800; text-transform: none; padding-top: 0; }
        .doc-file-manager { color: #111111; }
        .doc-file-manager-summary { cursor: pointer; list-style: none; display: inline-block; }
        .doc-file-manager-summary::-webkit-details-marker { display: none; }
        .doc-file-manager-hint { font-size: 0.8rem; font-weight: 600; color: #8c1109; margin-left: 8px; white-space: nowrap; }
        .doc-file-manager[open] .doc-file-manager-hint::after { content: " (đang mở)"; }
        .doc-file-manager-panel {
            margin-top: 12px; padding: 14px 16px; max-width: 760px;
            background: #fafbfc; border: 1px solid #e5e7eb; border-radius: 12px;
        }
        .doc-file-manager-panel h3 { margin: 0 0 10px; font-size: 1rem; color: #111111; }
        .doc-file-table-wrap { overflow-x: auto; }
        .doc-file-table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
        .doc-file-table th, .doc-file-table td { text-align: left; padding: 7px 8px; border-bottom: 1px solid #eef0f3; vertical-align: middle; }
        .doc-file-table th { color: #6b7280; font-size: 0.76rem; text-transform: uppercase; letter-spacing: 0.4px; }
        .doc-file-name { font-weight: 600; }
        .doc-file-inline-form { display: flex; gap: 6px; margin: 0; align-items: center; }
        .doc-file-rename-input { border: 1.5px solid #cbd2dc; border-radius: 6px; padding: 5px 8px; font-size: 0.86rem; min-width: 150px; }
        .doc-file-btn { background: #ffffff; border: 1.5px solid #111111; color: #111111; border-radius: 6px; padding: 5px 12px; font-weight: 600; font-size: 0.82rem; cursor: pointer; }
        .doc-file-btn:hover { background: #111111; color: #ffffff; }
        .doc-file-btn-delete { border-color: #b3160f; color: #b3160f; }
        .doc-file-btn-delete:hover { background: #b3160f; color: #ffffff; }
        .doc-file-upload-form { margin-top: 12px; }
        .doc-file-add-label { display: inline-flex; align-items: center; gap: 8px; cursor: pointer; font-weight: 700; color: #8c1109; border: 1.5px dashed #8c1109; border-radius: 8px; padding: 8px 14px; font-size: 0.86rem; }
        .doc-file-add-label input[type=file] { display: none; }
        .doc-file-note { margin-top: 10px; font-size: 0.82rem; }
        .profile-shell .profile-header-action-button,
        .profile-shell .title-doc-button {
            color: #11315f !important;
            background: #e9f2ff !important;
            border: 1.5px solid #8db4f5 !important;
            box-shadow: 0 6px 14px rgba(37, 99, 235, 0.12) !important;
        }
        .profile-shell .profile-header-action-button:hover,
        .profile-shell .title-doc-button:hover {
            background: #dbeafe !important;
            color: #0f2f66 !important;
        }
        .profile-shell .profile-header-action-button.is-active,
        .profile-shell .title-doc-button.is-active {
            background: #2563eb !important;
            border-color: #1d4ed8 !important;
            color: #ffffff !important;
        }
        .profile-shell .title-doc-actions .title-doc-dropdown {
            background: #ffffff !important;
            border: 1.5px solid #b3c6f7 !important;
            color: #111 !important;
            box-shadow: 0 10px 24px rgba(20, 30, 60, 0.12) !important;
        }
        .profile-shell .xl-tab-bar {
            background: #ffffff;
            border: 1px solid rgba(17, 17, 17, 0.14);
            border-bottom: 0;
            border-radius: 8px 8px 0 0;
        }
        .profile-shell .xl-tab-strip { border-bottom: 0 !important; }
        .profile-shell .xl-action-btn {
            width: auto;
            min-width: 32px;
            color: #111111;
            background: #ffffff;
            border: 1px solid rgba(17, 17, 17, 0.14);
            border-radius: 7px;
        }
        .profile-shell .xl-action-btn:hover { background: #f3f4f6; color: #111111; }
        .profile-shell .xl-action-btn.is-active {
            background: #f3f4f6;
            color: #111111;
            border-color: rgba(17, 17, 17, 0.24);
        }
        .profile-shell .xl-action-btn[data-profile-doc-search-toggle="true"] {
            min-width: 38px;
            font-size: 1.12rem;
            font-weight: 800;
        }
        .profile-shell .xl-action-btn-kind-switch {
            min-width: 42px;
            font-size: 0.86rem;
            font-weight: 800;
        }
        .profile-shell .xl-action-btn-edit {
            min-width: 36px;
            background: #ffffff;
            color: #111111;
            border: 1px solid rgba(17, 17, 17, 0.14);
            font-weight: 800;
        }
        .profile-shell .xl-action-btn-edit:hover,
        .profile-shell .xl-action-btn-edit.is-active {
            background: #f3f4f6;
            color: #000000;
            border: 1px solid rgba(17, 17, 17, 0.24);
        }
        .profile-shell .xl-action-btn-edit.is-disabled {
            background: transparent;
            color: #9ca3af;
            border: 1px solid rgba(17, 17, 17, 0.10);
            opacity: 1;
            cursor: not-allowed;
        }
        .profile-shell .xl-tab-actions .export-form {
            min-width: 0;
            width: auto;
            display: block;
            gap: 0;
        }
        .profile-shell .xl-tab-actions .export-form .xl-action-btn {
            width: 34px;
            min-width: 34px;
            padding: 0;
        }
        .profile-shell .xl-tab-actions .profile-toolbar-upload-form {
            position: relative;
        }
        .profile-shell .xl-tab-actions .profile-toolbar-upload-label {
            display: inline-grid;
            place-items: center;
            height: 34px;
            cursor: pointer;
            font-size: 1rem;
            font-weight: 800;
        }
        .profile-shell .profile-document-tab {
            background: #f5f7ff;
            border-color: #ccd5f0;
        }
        .profile-shell .profile-document-tab.is-active {
            background: #e2e9ff;
            border-color: #7096f0;
        }
        .profile-shell .profile-document-tab-button { color: #444; }
        .profile-shell .profile-document-tab.is-active .profile-document-tab-button { color: #1a3fa6; }
        .profile-shell .profile-document-tab-close { color: #888; }
        .profile-shell .profile-document-tab-close:hover { color: #d23030; }
        .profile-shell .xl-sheet thead th {
            background: #f7fafd;
            color: #1a56d6;
            border-bottom: 1.5px solid #b3c6f7;
        }
        .profile-shell .card.sheet-card {
            background: #ffffff;
            color: #111;
            border: 1px solid #e3e8f3;
            box-shadow: 0 6px 22px rgba(20, 30, 60, 0.06);
        }
        .profile-shell .sheet-head h1 { color: #0f1f3d; }
        .profile-shell .compact-panel { color: #111; }
        .profile-shell .xl-doc-add-dropdown {
            background: #ffffff;
            border: 1.5px solid #b3c6f7;
            box-shadow: 0 8px 24px rgba(20, 30, 60, 0.12);
        }
        .profile-shell .xl-doc-add-search {
            background: #ffffff;
            border: 1.5px solid #b3c6f7;
            color: #111;
        }
        .profile-shell .xl-doc-add-group-label { color: #1a56d6; }
        .profile-shell .xl-doc-add-item { color: #111; }
        .profile-shell .xl-doc-add-item:hover { background: #e1ecff; color: #1a56d6; }
        .profile-shell .xl-doc-add-empty { color: #888; }
        .spreadsheet-shell { max-width: 100%; width: 100%; box-sizing: border-box; overflow-x: hidden; }
        .profile-corners {
            display: flex;
            justify-content: space-between;
            align-items: start;
            gap: 18px;
            margin-bottom: 6px;
        }
        .left-rail {
            display: grid;
            gap: 10px;
        }
        .nav-rail-row, .doc-rail-row {
            display: flex;
            gap: 10px;
            align-items: center;
        }
        .rail-button {
            width: 50px;
            height: 50px;
            display: grid;
            place-items: center;
            border-radius: 999px;
            background: rgba(6, 15, 24, 0.88);
            border: 1.5px solid rgba(143, 247, 234, 0.34);
            color: #ffffff;
            text-decoration: none;
            font-size: 1.55rem;
            font-weight: 700;
            line-height: 1;
            box-shadow: 0 16px 28px rgba(0, 0, 0, 0.24);
        }
        .rail-back {
            font-family: inherit;
            cursor: pointer;
        }
        .rail-button:hover { color: #ffffff; }
        .profile-account-drawer { margin-left: auto; }
        .sheet-layout { display: grid; }
        .sheet-card { padding: 14px 16px 16px; }
        .sheet-head {
            display: flex;
            justify-content: space-between;
            gap: 16px;
            align-items: end;
            margin-bottom: 8px;
        }
        .profile-shell .sheet-head .profile-mode-title {
            margin: 0;
            color: #111111;
            font-size: 1.55rem;
            line-height: 1.08;
            font-weight: 900;
            letter-spacing: 0;
        }
        .sheet-head h1 { margin: 0; font-size: clamp(1.5rem, 2vw, 2.1rem); }
        .sheet-subtitle { margin: 6px 0 0; color: var(--muted); }
        .sheet-title-row {
            display: flex;
            align-items: center;
            gap: 12px;
            flex-wrap: wrap;
        }
        .title-doc-actions {
            display: flex;
            align-items: flex-end;
            gap: 8px;
        }
        .title-doc-actions > .panel-shell {
            display: flex;
            align-items: flex-end;
        }
        .profile-header-action-button {
            width: auto !important;
            height: 38px !important;
            min-width: 132px !important;
            min-height: 38px !important;
            padding: 0 14px !important;
            display: inline-flex !important;
            align-items: center !important;
            justify-content: center !important;
            align-self: flex-end;
            border-radius: 9px !important;
            text-decoration: none !important;
            font-size: 0.92rem;
            font-weight: 800;
            white-space: nowrap;
        }
        .profile-header-action-icon {
            width: 28px;
            height: 28px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            color: inherit;
        }
        .profile-header-action-icon svg {
            width: 28px;
            height: 28px;
            display: block;
        }
        .title-doc-button {
            width: auto;
            height: 38px;
            min-width: 132px;
            border-radius: 9px !important;
            filter: none;
        }
        @keyframes icon-pop {
            0%   { transform: scale(1); }
            35%  { transform: scale(1.22); }
            65%  { transform: scale(1.1); }
            100% { transform: scale(1.14); }
        }
        .dashboard-action-button:hover,
        .dashboard-control-button:hover,
        .title-doc-button:hover {
            animation: icon-pop 0.22s ease forwards;
            cursor: pointer;
        }
        /* title-doc dropdowns open to the right */
        .title-doc-dropdown {
            right: auto;
            left: 0;
            width: min(336px, calc(100vw - 28px));
            padding: 10px;
            background: var(--paper-strong) !important;
            border: 1px solid rgba(143, 247, 234, 0.24) !important;
            outline: none !important;
            box-shadow: 0 16px 32px rgba(0, 0, 0, 0.26) !important;
        }
        .title-doc-actions .title-doc-dropdown {
            background: var(--paper-strong) !important;
            border: 1px solid rgba(143, 247, 234, 0.24) !important;
            outline: none !important;
            box-shadow: 0 16px 32px rgba(0, 0, 0, 0.26) !important;
        }
        .title-doc-dropdown .document-list-card {
            background: transparent !important;
            border: none !important;
            box-shadow: none !important;
            padding: 0;
        }
        .sheet-actions { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
        .compact-qc-line { font-size: 0.82rem; letter-spacing: 0.04em; }
        .document-tabs { display: grid; gap: 12px; }
        .tab-strip { display: flex; gap: 8px; flex-wrap: wrap; }
        .tab-chip {
            width: auto;
            padding: 8px 14px;
            border-radius: 999px;
            background: rgba(255,255,255,0.06);
            color: var(--muted);
            box-shadow: none;
        }
        .tab-chip.is-active {
            background: rgba(61, 217, 197, 0.16);
            color: var(--accent-deep);
        }
        .tab-panel { display: none; }
        .tab-panel.is-active { display: block; }
        .document-list-card {
            border: 1px solid rgba(143, 247, 234, 0.10);
            border-radius: 18px;
            padding: 12px;
            background: rgba(255,255,255,0.03);
        }
        .doc-list-toolbar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            margin-bottom: 8px;
        }
        .doc-sync-btn {
            width: 30px;
            height: 30px;
            border-radius: 8px;
            border: 1px solid rgba(143, 247, 234, 0.2) !important;
            outline: none;
            box-shadow: none !important;
            appearance: none;
            background: var(--paper-strong) !important;
            color: var(--ink);
            font-size: 0.96rem;
            cursor: pointer;
            display: grid;
            place-items: center;
            padding: 0;
        }
        .doc-sync-btn:hover {
            background: var(--paper-strong) !important;
            color: var(--accent-deep);
            border: 1px solid rgba(143, 247, 234, 0.34) !important;
            outline: none !important;
            box-shadow: none !important;
        }
        .doc-sync-btn:focus,
        .doc-sync-btn:focus-visible,
        .doc-sync-btn:active {
            border: 1px solid rgba(143, 247, 234, 0.34) !important;
            outline: none !important;
            box-shadow: none !important;
        }
        .doc-sync-btn:disabled { opacity: 0.55; cursor: wait; }
        .doc-method-col-label {
            font-size: 0.76rem;
            letter-spacing: 0.03em;
            color: rgba(143,247,234,0.62);
            min-height: 1px;
        }
        .profile-empty-upload-form {
            margin: 0;
        }
        .profile-empty-upload-tile {
            display: inline-flex;
            flex-direction: row;
            align-items: center;
            gap: 6px;
            padding: 6px 12px 6px 8px;
            border-radius: 20px;
            border: 1px dashed rgba(143, 247, 234, 0.30);
            background: rgba(61, 217, 197, 0.06);
            cursor: pointer;
            white-space: nowrap;
            transition: border-color 160ms ease, background 160ms ease;
        }
        .profile-empty-upload-tile:hover {
            border-color: rgba(143, 247, 234, 0.50);
            background: rgba(61, 217, 197, 0.12);
        }
        .profile-empty-upload-input {
            position: absolute;
            width: 1px;
            height: 1px;
            opacity: 0;
            pointer-events: none;
        }
        .profile-empty-upload-plus {
            width: 22px;
            height: 22px;
            border-radius: 50%;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            background: rgba(61, 217, 197, 0.18);
            border: 1px solid rgba(143, 247, 234, 0.28);
            color: var(--accent-deep);
            font-size: 1.1rem;
            line-height: 1;
            font-weight: 400;
            flex-shrink: 0;
        }
        .profile-empty-upload-copy {
            font-size: 0.82rem;
            color: rgba(236, 246, 255, 0.84);
        }
        .document-name-list {
            list-style: none;
            margin: 0;
            padding: 0;
            display: grid;
            gap: 4px;
        }
        .doc-name-row {
            display: grid;
            grid-template-columns: 18px minmax(0, 1fr) 32px 24px;
            align-items: center;
            gap: 6px;
            padding: 6px 6px;
            border-radius: 9px;
            border: none;
            background: transparent;
            position: relative;
        }
        .doc-name-row:hover { background: transparent; }
        .doc-row-num {
            min-width: 18px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            font-size: 0.72rem;
            color: rgba(200,237,255,0.72);
            text-align: center;
            flex-shrink: 0;
            padding-top: 0;
            line-height: 1;
        }
        .doc-action-wrap {
            display: flex;
            align-items: flex-start;
            gap: 2px;
            flex-shrink: 0;
            position: relative;
            margin-top: 1px;
        }
        .doc-file-cell {
            border: 1px solid rgba(143, 247, 234, 0.2);
            border-radius: 8px;
            background: var(--paper-strong);
            padding: 5px 7px;
            min-height: 38px;
            display: flex;
            align-items: center;
        }
        .doc-file-cell:hover {
            border-color: rgba(143, 247, 234, 0.34);
        }
        .doc-method-wrap {
            display: flex;
            align-items: flex-start;
            justify-content: flex-start;
            min-width: 32px;
            max-width: 32px;
            flex: 0 0 32px;
            border: none;
            border-radius: 8px;
            background: transparent;
            padding: 0;
            position: relative;
        }
        .doc-method-pick {
            width: 28px;
            height: 28px;
            border-radius: 6px;
            border: 1px solid rgba(143, 247, 234, 0.2);
            box-shadow: none;
            background: var(--paper-strong);
            color: rgba(238,248,255,0.94);
            font-size: 0.98rem;
            font-weight: 700;
            cursor: pointer;
            line-height: 1;
            padding: 0;
        }
        .doc-method-pick:hover {
            color: #ffffff;
            background: var(--paper-strong);
            border-color: rgba(143, 247, 234, 0.34);
        }
        .doc-method-menu {
            position: absolute;
            z-index: 321;
            display: grid;
            gap: 2px;
            min-width: 190px;
            background: var(--paper-strong);
            border: 1px solid rgba(143, 247, 234, 0.2);
            border-radius: 10px;
            padding: 6px;
            box-shadow: 0 10px 22px rgba(0,0,0,0.32);
            top: calc(100% + 6px);
            left: 0;
            transform: none;
        }
        .doc-method-menu[hidden] { display: none !important; }
        .doc-method-item {
            border: 1px solid rgba(143, 247, 234, 0.16);
            background: var(--paper-strong);
            color: rgba(236,246,255,0.96);
            border-radius: 8px;
            padding: 6px 10px;
            text-align: left;
            font-size: 0.74rem;
            cursor: pointer;
            position: relative;
            display: grid;
            grid-template-columns: 14px minmax(0, 1fr);
            align-items: center;
            gap: 8px;
        }
        .doc-method-check {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 14px;
            min-width: 14px;
            color: rgba(236,246,255,0.94);
            opacity: 0;
            font-weight: 700;
        }
        .doc-method-item.is-selected .doc-method-check {
            opacity: 1;
        }
        .doc-method-item:hover {
            background: var(--paper-strong);
            border-color: rgba(143, 247, 234, 0.3);
        }
        .doc-action-bar {
            position: absolute;
            z-index: 320;
            display: flex;
            flex-direction: column;
            align-items: stretch;
            gap: 3px;
            background: var(--paper-strong);
            border: 1px solid rgba(143,247,234,0.22);
            border-radius: 10px;
            padding: 4px 6px;
            box-shadow: 0 4px 18px rgba(0,0,0,0.55);
            top: 4px;
            left: calc(100% + 2px);
            transform: none;
        }
        .doc-action-bar[hidden] { display: none !important; }
        .doc-more-btn {
            background: var(--paper-strong);
            border: 1px solid rgba(143,247,234,0.2);
            color: rgba(236,246,255,0.86);
            font-size: 1.1rem;
            line-height: 1;
            padding: 2px 5px;
            border-radius: 6px;
            cursor: pointer;
        }
        .doc-more-btn:hover {
            color: var(--accent-deep);
            background: var(--paper-strong);
            border-color: rgba(143,247,234,0.34);
        }
        .doc-act-btn {
            background: var(--paper-strong);
            border: 1px solid rgba(143,247,234,0.2);
            color: rgba(236,246,255,0.86);
            font-size: 0.9rem;
            width: 28px;
            height: 28px;
            border-radius: 7px;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 0;
        }
        .doc-act-btn:hover {
            background: var(--paper-strong);
            color: var(--accent-deep);
            border-color: rgba(105,244,207,0.4);
        }
        .doc-act-delete:hover { color: #ff6b6b; border-color: rgba(255,107,107,0.4); }
        .document-link {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            gap: 8px;
            padding: 0;
            border-radius: 0;
            text-decoration: none;
            color: var(--ink);
            flex: 1;
            min-width: 0;
        }
        .document-link:hover {
            color: var(--accent-deep);
        }
        .document-link-disabled {
            cursor: default;
            opacity: 0.72;
        }
        .document-filename {
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: normal;
            display: -webkit-box;
            -webkit-line-clamp: 2;
            -webkit-box-orient: vertical;
            line-height: 1.15;
            max-height: 2.35em;
        }
        .tiny-tag { padding: 4px 8px; font-size: 0.72rem; }
        .quick-preview-card {
            margin-top: 12px;
            border: 1px solid rgba(143, 247, 234, 0.10);
            border-radius: 18px;
            background: rgba(4, 10, 18, 0.84);
            padding: 12px;
            display: grid;
            gap: 10px;
        }
        .quick-preview-head {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 10px;
        }
        .quick-preview-body {
            max-height: 240px;
            overflow: auto;
            border-radius: 14px;
            background: rgba(255,255,255,0.03);
            border: 1px solid rgba(143, 247, 234, 0.08);
            padding: 12px;
        }
        .quick-preview-body pre {
            margin: 0;
            white-space: pre-wrap;
            word-break: break-word;
            font-family: Consolas, "Cascadia Code", monospace;
            color: rgba(236, 246, 255, 0.90);
        }
        .tiny-icon-button {
            width: 34px;
            height: 34px;
            min-width: 34px;
            font-size: 0.94rem;
        }
        .overlay-upload-form {
            margin-top: 12px;
            grid-template-columns: 2fr 100px 1fr auto;
            align-items: center;
        }
        .disabled { opacity: 0.44; pointer-events: none; }
        .visually-hidden {
            position: absolute;
            width: 1px;
            height: 1px;
            padding: 0;
            margin: -1px;
            overflow: hidden;
            clip: rect(0, 0, 0, 0);
            border: 0;
        }
        [hidden] { display: none !important; }
        .profile-preview-strip { margin-bottom: 14px; }
        .profile-preview-card { margin-top: 0; }
        .document-manager-page { display: grid; gap: 16px; }
        .document-manager-layout {
            display: grid;
            grid-template-columns: minmax(260px, 360px) 1fr;
            gap: 16px;
            align-items: start;
        }
        .empty-preview { margin-top: 0; }
        .profile-document-workspace {
            margin-bottom: 0;
            display: flex;
            flex-direction: column;
            gap: 0;
            border-radius: 0 0 22px 22px;
            overflow: hidden;
        }
        /* ── Excel Ribbon ── */
        .xl-ribbon {
            display: flex;
            flex-wrap: nowrap;
            align-items: stretch;
            background: #ffffff;
            border: 1px solid rgba(17, 17, 17, 0.14);
            border-top: 1px solid rgba(17, 17, 17, 0.14);
            border-bottom: 1px solid rgba(17, 17, 17, 0.14);
            padding: 7px 8px 6px;
            gap: 2px;
            max-height: 82px;
            overflow-x: auto;
            overflow-y: hidden;
            scrollbar-width: thin;
        }
        .xl-ribbon-group {
            display: flex;
            flex-direction: column;
            gap: 5px;
            align-items: flex-start;
            justify-content: center;
            padding: 4px 10px 5px;
            position: relative;
        }
        .xl-group-label {
            font-size: 0.64rem;
            color: #111111;
            text-align: center;
            width: 100%;
            margin-top: 1px;
            order: 99;
        }
        .xl-ribbon-sep {
            width: 1px;
            background: #111111;
            opacity: 0.22;
            margin: 4px 2px;
            align-self: stretch;
        }
        .xl-row {
            display: flex;
            gap: 4px;
            align-items: center;
        }
        .xl-btn {
            min-width: 28px;
            width: auto;
            height: 28px;
            padding: 0 8px;
            border-radius: 5px;
            border: 1px solid transparent;
            background: transparent;
            color: #111111;
            font-size: 0.82rem;
            box-shadow: none;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            white-space: nowrap;
        }
        .xl-btn:hover { background: #111111; border-color: #111111; color: #ffffff; transform: none; box-shadow: none; }
        .xl-btn.is-active { background: #111111; color: #ffffff; border-color: #111111; }
        .xl-btn-icon b, .xl-btn-icon i, .xl-btn-icon u, .xl-btn-icon s { font-size: 0.85rem; }
        .xl-select {
            height: 28px;
            padding: 0 8px;
            border-radius: 5px;
            border: 1px solid rgba(17, 17, 17, 0.18);
            background: #ffffff;
            color: #111111;
            font-size: 0.78rem;
        }
        .xl-font-name { min-width: 124px; }
        .xl-font-size { min-width: 58px; }
        .xl-num-format { min-width: 116px; }
        .xl-color-wrap { display: flex; align-items: center; }
        .xl-color-label {
            display: flex;
            flex-direction: column;
            align-items: center;
            cursor: pointer;
            gap: 1px;
            padding: 3px 5px;
            border-radius: 5px;
            border: 1px solid transparent;
        }
        .xl-color-label:hover { background: rgba(255,255,255,0.08); }
        .xl-color-label span { font-size: 0.82rem; line-height: 1; font-weight: 700; }
        .xl-color-input {
            width: 22px;
            height: 5px;
            padding: 0;
            border: none;
            border-radius: 2px;
            background: transparent;
            cursor: pointer;
        }
        /* ── Tab bar ── */
        .xl-tab-bar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 8px;
            background: #ffffff;
            border: 1px solid rgba(17, 17, 17, 0.14);
            border-bottom: 0;
            border-radius: 8px 8px 0 0;
            padding: 4px 8px;
            min-height: 38px;
        }
        .xl-tab-strip {
            display: flex;
            gap: 4px;
            align-items: center;
            flex: 1;
            overflow-x: auto;
            overflow-y: visible;
            scrollbar-width: none;
        }
        .xl-tab-strip::-webkit-scrollbar { display: none; }
        .xl-tab-actions {
            display: flex;
            gap: 4px;
            align-items: center;
            flex-shrink: 0;
            position: relative;
        }
        .xl-doc-add-shell {
            position: relative;
        }
        .xl-add-tab-btn {
            font-size: 1.1rem;
            font-weight: 700;
            padding: 0 9px;
        }
        .xl-doc-add-dropdown {
            position: fixed;
            z-index: 300;
            background: rgba(6,16,28,0.97);
            border: 1px solid rgba(143,247,234,0.22);
            border-radius: 14px;
            padding: 8px 6px;
            width: 240px;
            max-height: 320px;
            overflow-y: auto;
            display: flex;
            flex-direction: column;
            gap: 2px;
            box-shadow: 0 6px 28px rgba(0,0,0,0.55);
        }
        .xl-doc-add-search-row {
            padding: 0 4px 6px;
            border-bottom: 1px solid rgba(143,247,234,0.1);
            margin-bottom: 4px;
        }
        .xl-doc-add-search {
            width: 100%;
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(143,247,234,0.18);
            border-radius: 8px;
            padding: 5px 10px;
            color: var(--ink);
            font-size: 0.82rem;
            outline: none;
        }
        .xl-doc-add-search:focus { border-color: rgba(105,244,207,0.38); }
        .xl-doc-add-group-label {
            font-size: 0.68rem;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            color: rgba(143,247,234,0.5);
            padding: 6px 8px 2px;
        }
        .xl-doc-add-item {
            display: block;
            width: 100%;
            background: none;
            border: none;
            text-align: left;
            color: var(--ink);
            font-size: 0.82rem;
            padding: 6px 10px;
            border-radius: 8px;
            cursor: pointer;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        .xl-doc-add-item:hover { background: rgba(105,244,207,0.10); color: var(--accent-deep); }
        .xl-doc-add-item.is-recent { font-weight: 600; }
        .xl-doc-add-empty { padding: 10px; color: rgba(143,247,234,0.45); font-size: 0.8rem; text-align: center; }
        .xl-action-btn {
            min-width: 30px;
            height: 28px;
            padding: 0 8px;
            border-radius: 7px;
            border: 1px solid rgba(143,247,234,0.14);
            background: rgba(255,255,255,0.05);
            color: var(--ink);
            font-size: 0.88rem;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            text-decoration: none;
            box-shadow: none;
        }
        .xl-action-btn:hover { background: rgba(61,217,197,0.12); transform: none; box-shadow: none; }
        .xl-action-btn.is-active { background: rgba(61,217,197,0.18); color: var(--accent-deep); }
        .xl-search-shell {
            position: relative;
            display: inline-flex;
            align-items: center;
            width: auto;
            flex: 0 0 auto;
        }
        /* Tab items */
        .profile-document-tab {
            display: grid;
            grid-template-columns: minmax(0, 1fr) 22px;
            align-items: center;
            gap: 4px;
            padding: 5px 6px 5px 10px;
            border-radius: 8px;
            border: 1px solid transparent;
            background: transparent;
            max-width: 160px;
            min-width: 90px;
            flex-shrink: 0;
        }
        .profile-document-tab.is-active {
            border-color: rgba(105, 244, 207, 0.22);
            background: rgba(61, 217, 197, 0.10);
        }
        .profile-document-tab-button,
        .profile-document-tab-close {
            width: auto; min-width: 0; padding: 0; border: 0;
            background: transparent; color: inherit; box-shadow: none; text-align: left;
        }
        .profile-document-tab-button:hover, .profile-document-tab-close:hover { transform: none; box-shadow: none; }
        .profile-document-tab-button { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 0.80rem; color: rgba(236,246,255,0.75); }
        .profile-document-tab.is-active .profile-document-tab-button { color: var(--accent-deep); }
        .profile-document-tab-close { display: grid; place-items: center; height: 22px; border-radius: 999px; font-size: 0.82rem; color: rgba(236,246,255,0.45); }
        .profile-document-tab-close:hover { color: #ffffff; }
        /* ── Sheet shell ── */
        .xl-doc-search-bar {
            display: flex;
            align-items: center;
            gap: 8px;
            position: absolute;
            top: calc(100% + 7px);
            right: 0;
            z-index: 320;
            width: min(360px, calc(100vw - 32px));
            padding: 8px;
            background: #ffffff;
            border: 1px solid rgba(17, 17, 17, 0.14);
            border-radius: 8px;
            box-shadow: 0 14px 28px rgba(17, 24, 39, 0.16);
        }
        .xl-doc-search-bar[hidden] { display: none !important; }
        .xl-doc-search-input {
            flex: 1;
            padding: 6px 12px;
            border: 1px solid rgba(17, 17, 17, 0.16);
            border-radius: 6px;
            font-size: 0.92rem;
            background: #fff;
            color: #111;
            outline: none;
        }
        .xl-doc-search-input:focus { border-color: rgba(17, 17, 17, 0.34); box-shadow: inset 0 0 0 1px rgba(17, 17, 17, 0.18); }
        .xl-doc-search-count { font-size: 0.82rem; color: #111111; white-space: nowrap; }
        .xl-doc-search-close {
            display: grid;
            place-items: center;
            width: 24px;
            height: 24px;
            min-width: 24px;
            padding: 0;
            border: 1px solid rgba(17, 17, 17, 0.14);
            border-radius: 999px;
            background: #ffffff;
            color: #111111;
            font-size: 1rem;
            line-height: 1;
            box-shadow: none;
        }
        .xl-doc-search-close:hover { background: rgba(17, 17, 17, 0.06); transform: none; box-shadow: none; }
        tr.xl-search-hidden { display: none; }
        .xl-sheet-shell {
            position: relative;
            min-height: min(70vh, 800px);
            padding-bottom: 70px;
            overflow: auto;
            background:
                linear-gradient(180deg, rgba(4, 11, 18, 0.94), rgba(4, 11, 18, 0.94)),
                linear-gradient(90deg, rgba(61, 217, 197, 0.04), transparent 26%);
        }
        .profile-shell .xl-sheet-shell {
            background: #fff;
        }
        .xl-sheet-scroll { overflow: auto; }
        .xl-sheet {
            min-width: 100%;
            border-collapse: collapse;
            table-layout: fixed;
            margin: 0;
            font-family: "Times New Roman", Times, serif;
        }
        .xl-sheet thead th {
            position: sticky;
            top: 0;
            z-index: 1;
            background: rgba(6, 14, 23, 0.98);
            color: var(--accent-deep);
            font-size: 0.80rem;
            text-transform: uppercase;
            letter-spacing: 0.06em;
        }
        .xl-sheet th,
        .xl-sheet td {
            min-width: 120px;
            height: 40px;
            border: 1px solid rgba(143, 247, 234, 0.08);
            padding: 8px 10px;
            vertical-align: middle;
        }
        .xl-sheet td {
            color: rgba(236, 246, 255, 0.90);
            background: rgba(255,255,255,0.02);
            white-space: pre-wrap;
            word-break: break-word;
        }
        .xl-sheet td.is-editing {
            background: rgba(61, 217, 197, 0.06);
        }
        .xl-sheet td:focus {
            outline: 0;
            box-shadow: inset 0 0 0 2px rgba(105, 244, 207, 0.32);
            background: rgba(61, 217, 197, 0.10);
        }
        .profile-document-save-form { display: block; }
        .xl-save-fab {
            position: absolute;
            right: 18px;
            bottom: 18px;
            width: 52px; height: 52px; min-width: 52px;
            padding: 0;
            border-radius: 16px;
            box-shadow: 0 16px 30px rgba(0,0,0,0.28);
        }
        .sheet-table {
            table-layout: fixed;
            font-size: calc(0.96rem * var(--sheet-scale, 1));
            background: rgba(5, 12, 20, 0.46);
            border: 1px solid rgba(143, 247, 234, 0.12);
        }
        .sheet-table thead th {
            position: sticky;
            top: 0;
            z-index: 1;
            background: rgba(4, 12, 20, 0.96);
            color: var(--accent-deep);
        }
        .sheet-table th, .sheet-table td {
            padding: calc(12px * var(--sheet-scale, 1)) calc(10px * var(--sheet-scale, 1));
            border: 1px solid rgba(143, 247, 234, 0.08);
            vertical-align: middle;
            min-width: 120px;
        }
        .sheet-group-row td {
            background: rgba(61, 217, 197, 0.10);
            color: var(--accent-deep);
            font-weight: 700;
            letter-spacing: 0.06em;
            text-transform: uppercase;
        }
        /* dropdowns in title-doc-actions open to the right */
        .title-doc-actions .compact-panel { right: auto; left: 0; }
        .export-form {
            display: grid;
            gap: 10px;
            min-width: 240px;
        }
        form { display: grid; gap: 10px; }
        .stack { margin-top: 12px; }
        .inline-grid {
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 10px;
        }
        input, select, textarea, button {
            width: 100%;
            padding: 12px 14px;
            border-radius: 14px;
            border: 1px solid rgba(143, 247, 234, 0.10);
            background: rgba(255,255,255,0.05);
            color: var(--ink);
            font: inherit;
        }
        textarea { min-height: 84px; resize: vertical; }
        input:focus, select:focus, textarea:focus {
            outline: 2px solid rgba(61, 217, 197, 0.18);
            border-color: rgba(143, 247, 234, 0.34);
        }
        button {
            background: linear-gradient(135deg, rgba(61,217,197,0.96), rgba(82,145,255,0.82));
            color: #02141a;
            font-weight: 600;
            cursor: pointer;
            transition: transform 120ms ease, box-shadow 120ms ease;
        }
        button:hover { transform: translateY(-1px); box-shadow: 0 12px 24px rgba(61, 217, 197, 0.18); }
        button.secondary { background: linear-gradient(135deg, #ffb25b, #ff8f66); color: #101827; max-width: 220px; }
        button.compact { width: auto; min-width: 132px; }
        button.ghost {
            background: rgba(61, 217, 197, 0.10);
            color: var(--accent-deep);
            border: 1px solid rgba(61, 217, 197, 0.16);
            box-shadow: none;
        }
        button.strong-ghost { background: rgba(17, 72, 63, 0.12); }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 12px;
        }
        th, td {
            text-align: left;
            padding: 12px 10px;
            border-bottom: 1px solid var(--line);
            vertical-align: top;
        }
        .ok { color: var(--accent); font-weight: 700; }
        .error { color: #b91c1c; font-weight: 700; }
        .compact-login {
            width: min(332px, calc(100vw - 40px));
            padding: 0;
            display: grid;
            gap: 10px;
        }
        .login-card {
            background: #ffffff;
            border: 0;
            box-shadow: none;
            backdrop-filter: none;
            transition: border-color 160ms ease, box-shadow 160ms ease;
        }
        .login-error-flash {
            animation: login-error-pulse 0.5s ease;
        }
        .login-field {
            display: grid;
            grid-template-columns: 1fr;
            align-items: center;
            gap: 8px;
            min-height: 54px;
            padding: 0;
            border: 0;
            background: transparent;
            box-shadow: none;
        }
        .login-field input {
            min-height: 54px;
            width: 100%;
            border-radius: 8px;
            border: 2px solid #111111;
            background: #ffffff;
            padding: 0 16px;
            outline: none;
            box-shadow: none;
            color: #111111;
            caret-color: #111111;
            appearance: none;
            -webkit-appearance: none;
            -moz-appearance: none;
        }
        .login-field input::placeholder { color: #4b5563; }
        .login-field input:focus {
            outline: none;
            border-color: #111111;
            box-shadow: 0 0 0 2px rgba(17, 17, 17, 0.10);
        }
        .login-field input:-webkit-autofill,
        .login-field input:-webkit-autofill:hover,
        .login-field input:-webkit-autofill:focus,
        .login-field input:-webkit-autofill:active {
            -webkit-text-fill-color: #111111 !important;
            caret-color: #111111;
            border: 1.5px solid #111111 !important;
            -webkit-box-shadow: 0 0 0 1000px #ffffff inset !important;
            box-shadow: 0 0 0 1000px #ffffff inset !important;
            transition: background-color 9999s ease-out 0s;
        }
        .login-field-icon {
            display: grid;
            place-items: center;
            width: 30px;
            height: 30px;
            border-radius: 999px;
            color: var(--accent-deep);
            background: rgba(61, 217, 197, 0.08);
            border: 1px solid rgba(61, 217, 197, 0.12);
        }
        .login-submit {
            width: 52px;
            height: 52px;
            justify-self: center;
            border-radius: 8px;
            padding: 0;
            display: grid;
            place-items: center;
            color: #111111;
            background: #ffffff;
            border: 2px solid #111111;
            box-shadow: none;
            transition: transform 140ms ease, box-shadow 140ms ease, filter 140ms ease;
        }
        .login-submit:hover:not(:disabled) {
            transform: translateY(-1px);
            box-shadow: 0 8px 18px rgba(17, 17, 17, 0.10);
            filter: none;
        }
        .login-submit:disabled {
            opacity: 0.56;
            cursor: not-allowed;
        }
        .login-submit-icon {
            width: 28px;
            height: 28px;
            overflow: visible;
        }
        .login-submit-bracket {
            fill: none;
            stroke: currentColor;
            stroke-width: 4.2;
            stroke-linecap: round;
            stroke-linejoin: round;
        }
        .login-submit-arrow-shaft,
        .login-submit-arrow-head {
            fill: none;
            stroke: currentColor;
            stroke-width: 4.2;
            stroke-linecap: round;
            stroke-linejoin: round;
        }
        .login-submit-arrow-head {
            stroke-width: 4.6;
        }
        .login-wait-message {
            margin: 0;
            text-align: center;
            color: #ffb25b;
            font-weight: 700;
            letter-spacing: 0.04em;
        }
        @keyframes login-error-pulse {
            0% { border-color: rgba(255, 89, 89, 0.14); box-shadow: var(--shadow); }
            45% { border-color: rgba(255, 89, 89, 0.98); box-shadow: 0 0 0 1px rgba(255, 89, 89, 0.96), 0 0 28px rgba(255, 89, 89, 0.24); }
            100% { border-color: rgba(255, 89, 89, 0.14); box-shadow: var(--shadow); }
        }
        @media (max-width: 720px) {
            .inline-grid { grid-template-columns: 1fr; }
            .details { grid-template-columns: 1fr; }
            .shell, .login-shell, .command-shell { padding: 16px; }
            .graph-stage, .graph-card, .tree-canvas { min-height: calc(100vh - 32px); }
            .floating-controls { top: 14px; right: 14px; }
            .org-svg { min-height: 56vh; }
            .profile-corners, .sheet-head, .sheet-title-row, .profile-right-tools { flex-direction: column; align-items: stretch; }
            .overlay-panel { inset: 82px 12px 12px 12px; }
            .overlay-upload-form, .crypto-grid, .document-manager-layout { grid-template-columns: 1fr; }
            .top-control-row, .nav-rail-row, .doc-rail-row { flex-wrap: wrap; }
        }
    "#
}

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct CsrfForm {
    csrf: String,
    #[serde(default)]
    return_to: String,
}

#[derive(Deserialize)]
struct OrgForm {
    csrf: String,
    name: String,
    category: String,
    tier: u32,
    username: String,
    password: String,
    role: String,
    tree_key_enabled: Option<String>,
    admin_key: String,
    #[serde(default)]
    return_to: String,
}

#[derive(Deserialize)]
struct MemberForm {
    csrf: String,
    full_name: String,
    title: String,
    year: i32,
    notes: String,
    #[serde(default)]
    birth_date: String,
    #[serde(default)]
    address: String,
    #[serde(default)]
    phone: String,
    #[serde(default)]
    joined_at: String,
    #[serde(default)]
    return_to: String,
}

#[derive(Deserialize)]
struct ActivityForm {
    csrf: String,
    title: String,
    year: i32,
    status: String,
    summary: String,
    #[serde(default)]
    return_to: String,
}

#[derive(Deserialize)]
struct UserForm {
    csrf: String,
    username: String,
    password: String,
    role: String,
    org_id: String,
    tree_key_enabled: Option<String>,
    #[serde(default)]
    return_to: String,
}

#[derive(Deserialize)]
struct DownloadForm {
    access_key: String,
}

#[derive(Deserialize)]
struct MemberExportForm {
    csrf: String,
}

#[derive(Deserialize)]
struct DocumentUnlockForm {
    csrf: String,
    password: String,
}

#[derive(Deserialize)]
struct MemberUpdateForm {
    csrf: String,
    full_name: String,
    title: String,
    #[serde(default)]
    birth_date: String,
    #[serde(default)]
    address: String,
    #[serde(default)]
    phone: String,
    #[serde(default)]
    joined_at: String,
    #[serde(default)]
    notes: String,
    active: Option<String>,
    #[serde(default)]
    return_to: String,
}

/// Đích chuyển hướng sau khi thao tác ghi: dùng return_to nội bộ nếu hợp lệ,
/// nếu không thì về trang chủ.
fn redirect_back(return_to: &str) -> Response {
    let target = sanitize_local_return_target(return_to).unwrap_or_else(|| "/".to_owned());
    Redirect::to(&target).into_response()
}

fn normalize_sync_key(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    let bytes = STANDARD.decode(trimmed).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    Some(trimmed.to_owned())
}

fn header_sync_key(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-browser-sync-key")
        .and_then(|value| value.to_str().ok())
        .and_then(normalize_sync_key)
}

fn validate_sync_request_headers(headers: &HeaderMap, require_https: bool) -> anyhow::Result<()> {
    let requested_with = headers
        .get("x-requested-with")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if requested_with != "XMLHttpRequest" {
        return Err(anyhow!("missing sync request marker"));
    }

    if require_https {
        let forwarded_proto = headers
            .get("x-forwarded-proto")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        if !forwarded_proto.eq_ignore_ascii_case("https") {
            return Err(anyhow!("sync bootstrap requires https"));
        }
    }

    Ok(())
}

fn parse_rfc3339_utc(value: &str) -> Option<DateTime<Utc>> {
    chrono::DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|item| item.with_timezone(&Utc))
}

fn timestamp_is_after(value: &str, since: Option<&DateTime<Utc>>) -> bool {
    let Some(since) = since else {
        return true;
    };
    parse_rfc3339_utc(value).is_some_and(|timestamp| timestamp > *since)
}

fn latest_timestamp<'a>(values: impl IntoIterator<Item = &'a str>) -> Option<String> {
    values
        .into_iter()
        .filter_map(parse_rfc3339_utc)
        .max()
        .map(|timestamp| timestamp.to_rfc3339())
}

fn latest_snapshot_timestamp(snapshot: &SyncSnapshot) -> Option<String> {
    latest_timestamp(
        snapshot
            .organizations
            .iter()
            .map(|item| item.updated_at.as_str())
            .chain(snapshot.members.iter().map(|item| item.updated_at.as_str()))
            .chain(
                snapshot
                    .activities
                    .iter()
                    .map(|item| item.updated_at.as_str()),
            )
            .chain(
                snapshot
                    .documents
                    .iter()
                    .map(|item| item.updated_at.as_str()),
            ),
    )
}

fn build_visible_sync_snapshot(
    user: &User,
    data: &AppData,
    since: Option<&DateTime<Utc>>,
) -> SyncSnapshot {
    let visible_ids = tree_visible_ids(user, data);
    SyncSnapshot {
        organizations: data
            .organizations
            .iter()
            .filter(|item| {
                visible_ids.contains(&item.id) && timestamp_is_after(&item.updated_at, since)
            })
            .cloned()
            .collect(),
        members: data
            .members
            .iter()
            .filter(|item| {
                visible_ids.contains(&item.org_id) && timestamp_is_after(&item.updated_at, since)
            })
            .cloned()
            .collect(),
        activities: data
            .activities
            .iter()
            .filter(|item| {
                visible_ids.contains(&item.org_id) && timestamp_is_after(&item.updated_at, since)
            })
            .cloned()
            .collect(),
        documents: data
            .documents
            .iter()
            .filter(|item| {
                visible_ids.contains(&item.org_id) && timestamp_is_after(&item.updated_at, since)
            })
            .cloned()
            .collect(),
    }
}

fn forbidden_network_response() -> Response {
    (
        StatusCode::FORBIDDEN,
        Html(
            "<h1>403</h1><p>Che do LAN-only dang bat, chi chap nhan truy cap tu mang noi bo.</p>"
                .to_owned(),
        ),
    )
        .into_response()
}

fn parse_ip_whitelist(raw: &str) -> anyhow::Result<Vec<IpAddr>> {
    raw.split(|ch: char| ch == ',' || ch == ';' || ch == '\n' || ch == '\r' || ch.is_whitespace())
        .filter(|segment| !segment.trim().is_empty())
        .map(|segment| {
            segment
                .trim()
                .parse::<IpAddr>()
                .map_err(|_| anyhow::anyhow!("invalid ip address: {}", segment.trim()))
        })
        .collect()
}

fn is_allowed_lan_ip(ip: IpAddr, ip_whitelist: &[IpAddr]) -> bool {
    if ip_whitelist.contains(&ip) {
        return true;
    }
    match ip {
        IpAddr::V4(ipv4) => ipv4.is_loopback() || ipv4.is_private() || ipv4.is_link_local(),
        IpAddr::V6(ipv6) => {
            ipv6.is_loopback() || ipv6.is_unique_local() || ipv6.is_unicast_link_local()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AppConfig, AppData, AppState, EncryptedSyncEnvelope, NetworkMode, NetworkSettings,
        SyncPayload, build_router, hash_password, is_allowed_lan_ip,
    };
    use crate::{
        crypto::{MasterKey, verify_password},
        hybird::{decrypt_document, decrypt_transport_payload, load_or_create_kem_pair},
        models::{Document, Organization, User, UserRole, now_string},
        storage::Storage,
        web::{
            ProfileAccess, profile_access, tree_visible_ids,
            visible_org_ids,
        },
    };
    use axum::{
        body::{Body, to_bytes},
        extract::ConnectInfo,
        http::{Request, StatusCode, header},
    };
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use std::{
        collections::HashMap,
        net::{IpAddr, Ipv4Addr, SocketAddr},
        path::PathBuf,
        sync::Arc,
    };
    use tokio::sync::RwLock;
    use tower::util::ServiceExt;

    struct TestHarness {
        state: AppState,
        private_key_b64: String,
        base_dir: PathBuf,
    }

    fn test_harness(network_mode: NetworkMode) -> TestHarness {
        let base_dir = std::env::temp_dir().join(format!(
            "website_buu_test_{}",
            crate::models::new_id("state")
        ));
        let storage = Arc::new(Storage::new(&base_dir, MasterKey([7_u8; 32])).expect("storage"));
        let key_dir = base_dir.join("keys");
        let master_key = MasterKey([7_u8; 32]);
        let (public_key, private_key) = load_or_create_kem_pair(&key_dir, &master_key).expect("kem pair");
        let data = AppData {
            organizations: Vec::new(),
            users: vec![User {
                id: "user-test-admin".to_owned(),
                username: "admin".to_owned(),
                password_hash: hash_password("admin").expect("password hash"),
                role: UserRole::RootAdmin,
                org_id: None,
                tree_key_enabled: true,
                active: true,
                created_at: now_string(),
            }],
            members: Vec::new(),
            activities: Vec::new(),
            documents: Vec::new(),
        };

        TestHarness {
            state: AppState {
                data: Arc::new(RwLock::new(data)),
                storage,
                sessions: Arc::new(RwLock::new(HashMap::new())),
                login_attempts: Arc::new(RwLock::new(HashMap::new())),
                dashboard_tree_states: Arc::new(RwLock::new(HashMap::new())),
                dashboard_tree_state_path: Arc::new(base_dir.join("dashboard_tree_states.json")),
                network_settings: Arc::new(RwLock::new(NetworkSettings {
                    mode: network_mode,
                    ip_whitelist: vec![],
                })),
                config: AppConfig {
                    bind_addr: "127.0.0.1:8080".to_owned(),
                    tree_admin_key: "test-tree-key".to_owned(),
                    kem_public_key: public_key.clone(),
                    require_https: false,
                },
            },
            private_key_b64: private_key,
            base_dir,
        }
    }

    impl Drop for TestHarness {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.base_dir);
        }
    }

    async fn login_and_get_session_with_sync_key(
        app: &axum::Router,
        state: &AppState,
        username: &str,
        password: &str,
    ) -> (String, String) {
        let form_body = format!("username={username}&password={password}");
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/login")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(form_body))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let cookie_header = response
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        let session_cookie = cookie_header
            .split(';')
            .next()
            .unwrap_or_default()
            .to_owned();
        assert!(session_cookie.starts_with("session_id="));

        let user_id = state
            .data
            .read()
            .await
            .users
            .iter()
            .find(|user| user.username == username)
            .map(|user| user.id.clone())
            .unwrap_or_default();
        assert!(!user_id.is_empty());

        let csrf = state
            .sessions
            .read()
            .await
            .values()
            .find(|session| session.user_id == user_id)
            .map(|session| session.csrf_token.clone())
            .unwrap_or_default();
        assert!(!csrf.is_empty());
        (session_cookie, csrf)
    }

    async fn login_and_get_session(
        app: &axum::Router,
        state: &AppState,
        username: &str,
        password: &str,
    ) -> (String, String) {
        login_and_get_session_with_sync_key(app, state, username, password).await
    }

    fn cookie_header(session_id: &str) -> String {
        session_id.to_owned()
    }

    fn encode_form_value(value: &str) -> String {
        value
            .replace('%', "%25")
            .replace('+', "%2B")
            .replace(' ', "+")
            .replace('/', "%2F")
            .replace('=', "%3D")
    }

    fn multipart_body(
        fields: &[(&str, &str)],
        file_name: &str,
        file_content_type: &str,
        file_bytes: &[u8],
    ) -> (String, Vec<u8>) {
        let boundary = format!("----website-buu-{}", crate::models::new_id("boundary"));
        let mut body = Vec::new();

        for (name, value) in fields {
            body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
            body.extend_from_slice(
                format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n")
                    .as_bytes(),
            );
        }

        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(
            format!(
                "Content-Disposition: form-data; name=\"document\"; filename=\"{file_name}\"\r\nContent-Type: {file_content_type}\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(file_bytes);
        body.extend_from_slice(b"\r\n");
        body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
        (boundary, body)
    }

    #[test]
    fn lan_filter_accepts_private_ipv4() {
        assert!(is_allowed_lan_ip(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            &[]
        ));
        assert!(is_allowed_lan_ip(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            &[]
        ));
        assert!(is_allowed_lan_ip(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            &[]
        ));
    }

    #[test]
    fn lan_filter_rejects_public_ipv4() {
        assert!(!is_allowed_lan_ip(
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            &[]
        ));
        assert!(!is_allowed_lan_ip(
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            &[]
        ));
    }

    #[test]
    fn lan_filter_accepts_whitelisted_public_ip() {
        let whitelist = vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))];
        assert!(is_allowed_lan_ip(
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            &whitelist
        ));
    }

    #[test]
    fn network_mode_string_is_stable() {
        assert_eq!(NetworkMode::InternetTest.as_str(), "internet-test");
        assert_eq!(NetworkMode::LanOnly.as_str(), "lan-only");
    }

    #[tokio::test]
    async fn health_route_returns_ok_in_internet_mode() {
        let harness = test_harness(NetworkMode::InternetTest);
        let app = build_router(harness.state.clone());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-store, no-cache, must-revalidate")
        );
    }

    #[tokio::test]
    async fn lan_only_rejects_public_client_ip() {
        let harness = test_harness(NetworkMode::LanOnly);
        let app = build_router(harness.state.clone());
        let mut request = Request::builder()
            .uri("/health")
            .body(Body::empty())
            .expect("request");
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([8, 8, 8, 8], 40000))));

        let response = app.oneshot(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn root_admin_can_toggle_network_mode_at_runtime() {
        let harness = test_harness(NetworkMode::InternetTest);
        let app = build_router(harness.state.clone());
        let (session_id, csrf) =
            login_and_get_session(&app, &harness.state, "admin", "admin").await;
        let session_cookie = cookie_header(&session_id);

        let enable_lan_response = app
            .clone()
            .oneshot({
                let mut request = Request::builder()
                    .method("POST")
                    .uri("/settings/network")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .header(header::COOKIE, &session_cookie)
                    .body(Body::from(format!(
                        "csrf={}&mode=lan-only&ip_whitelist=",
                        encode_form_value(&csrf)
                    )))
                    .expect("request");
                request
                    .extensions_mut()
                    .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40000))));
                request
            })
            .await
            .expect("response");
        assert_eq!(enable_lan_response.status(), StatusCode::OK);

        let mut public_request = Request::builder()
            .uri("/health")
            .body(Body::empty())
            .expect("request");
        public_request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([8, 8, 8, 8], 40001))));
        let public_response = app.clone().oneshot(public_request).await.expect("response");
        assert_eq!(public_response.status(), StatusCode::FORBIDDEN);

        let enable_internet_response = app
            .clone()
            .oneshot({
                let mut request = Request::builder()
                    .method("POST")
                    .uri("/settings/network")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .header(header::COOKIE, &session_cookie)
                    .body(Body::from(format!(
                        "csrf={}&mode=internet-test&ip_whitelist={}",
                        encode_form_value(&csrf),
                        encode_form_value("8.8.8.8")
                    )))
                    .expect("request");
                request
                    .extensions_mut()
                    .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40003))));
                request
            })
            .await
            .expect("response");
        assert_eq!(enable_internet_response.status(), StatusCode::OK);

        let mut public_request_after = Request::builder()
            .uri("/health")
            .body(Body::empty())
            .expect("request");
        public_request_after
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([8, 8, 8, 8], 40002))));
        let public_response_after = app.oneshot(public_request_after).await.expect("response");
        assert_eq!(public_response_after.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn login_sets_session_cookie_for_valid_user() {
        let harness = test_harness(NetworkMode::InternetTest);
        let app = build_router(harness.state.clone());
        let (session_id, csrf) =
            login_and_get_session(&app, &harness.state, "admin", "admin").await;
        assert!(!session_id.is_empty());
        assert!(!csrf.is_empty());
    }

    #[tokio::test]
    async fn user_can_change_own_password() {
        let harness = test_harness(NetworkMode::InternetTest);
        {
            let mut data = harness.state.data.write().await;
            data.users.push(User {
                id: "user-manager".to_owned(),
                username: "manager".to_owned(),
                password_hash: hash_password("Manager@123").expect("hash"),
                role: UserRole::OrgManager,
                org_id: Some("org-root".to_owned()),
                tree_key_enabled: false,
                active: true,
                created_at: now_string(),
            });
        }

        let app = build_router(harness.state.clone());
        let (session_id, csrf) =
            login_and_get_session(&app, &harness.state, "manager", "Manager%40123").await;
        let session_cookie = cookie_header(&session_id);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/settings/password")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .header(header::COOKIE, &session_cookie)
                    .body(Body::from(format!(
                        "csrf={}&current_password={}&new_password={}&confirm_password={}",
                        encode_form_value(&csrf),
                        encode_form_value("Manager@123"),
                        encode_form_value("NewPass@456"),
                        encode_form_value("NewPass@456")
                    )))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);

        let data = harness.state.data.read().await;
        let user = data
            .users
            .iter()
            .find(|user| user.username == "manager")
            .expect("updated user");
        assert!(verify_password(&user.password_hash, "NewPass@456"));
        assert!(!verify_password(&user.password_hash, "Manager@123"));
    }

    #[tokio::test]
    async fn user_can_change_password_to_short_value() {
        let harness = test_harness(NetworkMode::InternetTest);
        {
            let mut data = harness.state.data.write().await;
            data.users.push(User {
                id: "user-short-password".to_owned(),
                username: "shortpwd".to_owned(),
                password_hash: hash_password("Temp@123").expect("hash"),
                role: UserRole::OrgManager,
                org_id: Some("org-root".to_owned()),
                tree_key_enabled: false,
                active: true,
                created_at: now_string(),
            });
        }

        let app = build_router(harness.state.clone());
        let (session_id, csrf) =
            login_and_get_session(&app, &harness.state, "shortpwd", "Temp%40123").await;
        let session_cookie = cookie_header(&session_id);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/settings/password")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .header(header::COOKIE, &session_cookie)
                    .body(Body::from(format!(
                        "csrf={}&current_password={}&new_password={}&confirm_password={}",
                        encode_form_value(&csrf),
                        encode_form_value("Temp@123"),
                        encode_form_value("0"),
                        encode_form_value("0")
                    )))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);

        let data = harness.state.data.read().await;
        let user = data
            .users
            .iter()
            .find(|user| user.username == "shortpwd")
            .expect("updated user");
        assert!(verify_password(&user.password_hash, "0"));
    }

    #[tokio::test]
    async fn legacy_default_code_is_rejected_after_password_change() {
        let harness = test_harness(NetworkMode::InternetTest);
        {
            let mut data = harness.state.data.write().await;
            data.users.push(User {
                id: "user-legacy-lockout".to_owned(),
                username: "0".to_owned(),
                password_hash: hash_password("0").expect("hash"),
                role: UserRole::OrgManager,
                org_id: Some("org-root".to_owned()),
                tree_key_enabled: false,
                active: true,
                created_at: now_string(),
            });
        }

        let app = build_router(harness.state.clone());
        let (session_id, csrf) = login_and_get_session(&app, &harness.state, "0", "0").await;
        let session_cookie = cookie_header(&session_id);

        let change_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/settings/password")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .header(header::COOKIE, &session_cookie)
                    .body(Body::from(format!(
                        "csrf={}&current_password={}&new_password={}&confirm_password={}",
                        encode_form_value(&csrf),
                        encode_form_value("0"),
                        encode_form_value("00"),
                        encode_form_value("00")
                    )))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(change_response.status(), StatusCode::OK);

        let old_password_login = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/login")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from("username=0&password=0"))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(old_password_login.status(), StatusCode::OK);

        let new_password_login = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/login")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from("username=0&password=00"))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(new_password_login.status(), StatusCode::SEE_OTHER);
    }

    #[tokio::test]
    async fn org_manager_can_modify_descendant_but_not_other_branch() {
        let harness = test_harness(NetworkMode::InternetTest);
        {
            let mut data = harness.state.data.write().await;
            data.organizations = vec![
                Organization {
                    id: "org-root".to_owned(),
                    parent_id: None,
                    name: "Root".to_owned(),
                    tier: 1,
                    category: "cap 1".to_owned(),
                    active: true,
                    created_at: now_string(),
                    updated_at: now_string(),
                },
                Organization {
                    id: "org-child".to_owned(),
                    parent_id: Some("org-root".to_owned()),
                    name: "Child".to_owned(),
                    tier: 2,
                    category: "cap 2".to_owned(),
                    active: true,
                    created_at: now_string(),
                    updated_at: now_string(),
                },
                Organization {
                    id: "org-other".to_owned(),
                    parent_id: None,
                    name: "Other".to_owned(),
                    tier: 1,
                    category: "khac".to_owned(),
                    active: true,
                    created_at: now_string(),
                    updated_at: now_string(),
                },
            ];
            data.users.push(User {
                id: "user-manager".to_owned(),
                username: "manager".to_owned(),
                password_hash: hash_password("Manager@123").expect("hash"),
                role: UserRole::OrgManager,
                org_id: Some("org-root".to_owned()),
                tree_key_enabled: false,
                active: true,
                created_at: now_string(),
            });
        }

        let app = build_router(harness.state.clone());
        let (session_id, csrf) =
            login_and_get_session(&app, &harness.state, "manager", "Manager%40123").await;
        let session_cookie = cookie_header(&session_id);

        let allowed = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/orgs/org-child/members")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .header(header::COOKIE, &session_cookie)
                    .body(Body::from(format!(
                        "csrf={}&full_name={}&title={}&year=2026&notes={}",
                        encode_form_value(&csrf),
                        encode_form_value("Thanh Vien 1"),
                        encode_form_value("Pho ban"),
                        encode_form_value("duoc phep")
                    )))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(allowed.status(), StatusCode::SEE_OTHER);

        let denied = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/orgs/org-other/members")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .header(header::COOKIE, &session_cookie)
                    .body(Body::from(format!(
                        "csrf={}&full_name={}&title={}&year=2026&notes={}",
                        encode_form_value(&csrf),
                        encode_form_value("Thanh Vien 2"),
                        encode_form_value("Pho ban"),
                        encode_form_value("khong duoc")
                    )))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(denied.status(), StatusCode::SEE_OTHER);

        let data = harness.state.data.read().await;
        assert_eq!(data.members.len(), 1);
        assert_eq!(data.members[0].org_id, "org-child");
    }

    #[tokio::test]
    async fn org_manager_visibility_stays_within_own_branch() {
        let harness = test_harness(NetworkMode::InternetTest);
        let manager = {
            let mut data = harness.state.data.write().await;
            data.organizations = vec![
                Organization {
                    id: "org-root".to_owned(),
                    parent_id: None,
                    name: "Root".to_owned(),
                    tier: 0,
                    category: "cap 0".to_owned(),
                    active: true,
                    created_at: now_string(),
                    updated_at: now_string(),
                },
                Organization {
                    id: "org-branch-a".to_owned(),
                    parent_id: Some("org-root".to_owned()),
                    name: "Branch A".to_owned(),
                    tier: 1,
                    category: "cap 1".to_owned(),
                    active: true,
                    created_at: now_string(),
                    updated_at: now_string(),
                },
                Organization {
                    id: "org-branch-a-child".to_owned(),
                    parent_id: Some("org-branch-a".to_owned()),
                    name: "Branch A Child".to_owned(),
                    tier: 2,
                    category: "cap 2".to_owned(),
                    active: true,
                    created_at: now_string(),
                    updated_at: now_string(),
                },
                Organization {
                    id: "org-branch-b".to_owned(),
                    parent_id: Some("org-root".to_owned()),
                    name: "Branch B".to_owned(),
                    tier: 1,
                    category: "cap 1".to_owned(),
                    active: true,
                    created_at: now_string(),
                    updated_at: now_string(),
                },
            ];
            let manager = User {
                id: "user-branch-a-manager".to_owned(),
                username: "branch-a".to_owned(),
                password_hash: hash_password("Branch@123").expect("hash"),
                role: UserRole::OrgManager,
                org_id: Some("org-branch-a".to_owned()),
                tree_key_enabled: true,
                active: true,
                created_at: now_string(),
            };
            data.users.push(manager.clone());
            manager
        };

        let data = harness.state.data.read().await;

        let visible_ids = visible_org_ids(&manager, &data);
        assert!(visible_ids.contains("org-branch-a"));
        assert!(visible_ids.contains("org-branch-a-child"));
        assert!(!visible_ids.contains("org-root"));
        assert!(!visible_ids.contains("org-branch-b"));

        let tree_ids = tree_visible_ids(&manager, &data);
        assert!(tree_ids.contains("org-root"));
        assert!(tree_ids.contains("org-branch-a"));
        assert!(tree_ids.contains("org-branch-a-child"));
        assert!(!tree_ids.contains("org-branch-b"));

        assert!(matches!(
            profile_access(&manager, "org-branch-a", &data),
            Some(ProfileAccess::Full)
        ));
        assert!(matches!(
            profile_access(&manager, "org-branch-a-child", &data),
            Some(ProfileAccess::Full)
        ));
        assert!(matches!(
            profile_access(&manager, "org-root", &data),
            Some(ProfileAccess::Limited)
        ));
        assert!(profile_access(&manager, "org-branch-b", &data).is_none());
    }

    #[tokio::test]
    async fn document_upload_rejects_non_leaf_orgs_and_download_round_trip_succeeds_for_leaf() {
        let harness = test_harness(NetworkMode::InternetTest);
        {
            let mut data = harness.state.data.write().await;
            data.organizations.push(Organization {
                id: "org-doc-parent".to_owned(),
                parent_id: None,
                name: "Document Parent".to_owned(),
                tier: 1,
                category: "van ban".to_owned(),
                active: true,
                created_at: now_string(),
                updated_at: now_string(),
            });
            data.organizations.push(Organization {
                id: "org-doc-leaf".to_owned(),
                parent_id: Some("org-doc-parent".to_owned()),
                name: "Document Leaf".to_owned(),
                tier: 2,
                category: "van ban".to_owned(),
                active: true,
                created_at: now_string(),
                updated_at: now_string(),
            });
        }

        let app = build_router(harness.state.clone());
        let (session_id, csrf) =
            login_and_get_session(&app, &harness.state, "admin", "admin").await;
        let session_cookie = cookie_header(&session_id);
        let plaintext = b"bao cao noi bo 2026";
        let (parent_boundary, parent_body) = multipart_body(
            &[
                ("csrf", &csrf),
                ("title", "Bao cao cap tren"),
                ("org_id", "org-doc-parent"),
                ("year", "2026"),
            ],
            "report-parent.txt",
            "text/plain",
            plaintext,
        );

        let denied_upload_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/documents")
                    .header(header::COOKIE, &session_cookie)
                    .header(
                        header::CONTENT_TYPE,
                        format!("multipart/form-data; boundary={parent_boundary}"),
                    )
                    .body(Body::from(parent_body))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(denied_upload_response.status(), StatusCode::SEE_OTHER);
        {
            let data = harness.state.data.read().await;
            assert!(data.documents.is_empty());
        }

        let (boundary, body) = multipart_body(
            &[
                ("csrf", &csrf),
                ("title", "Bao cao tong ket"),
                ("org_id", "org-doc-leaf"),
                ("year", "2026"),
                ("return_to", "/units/org-doc-leaf?panel=unit-docs"),
            ],
            "report.txt",
            "text/plain",
            plaintext,
        );

        let upload_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/documents")
                    .header(header::COOKIE, &session_cookie)
                    .header(
                        header::CONTENT_TYPE,
                        format!("multipart/form-data; boundary={boundary}"),
                    )
                    .body(Body::from(body))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(upload_response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            upload_response
                .headers()
                .get(header::LOCATION)
                .and_then(|value| value.to_str().ok()),
            Some("/units/org-doc-leaf?panel=unit-docs")
        );

        let document: Document = {
            let data = harness.state.data.read().await;
            assert_eq!(data.documents.len(), 1);
            data.documents[0].clone()
        };
        let encrypted = std::fs::read(&document.encrypted_path).expect("encrypted file");
        let direct_plaintext = decrypt_document(
            &harness.private_key_b64,
            &document.kem_ciphertext_b64,
            &document.nonce_b64,
            &encrypted,
        )
        .expect("direct decrypt");
        assert_eq!(direct_plaintext.as_slice(), plaintext);

        let download_body = format!("access_key={}", encode_form_value(&harness.private_key_b64));
        let download_response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/documents/{}/download", document.id))
                    .header(header::COOKIE, &session_cookie)
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(download_body))
                    .expect("request"),
            )
            .await
            .expect("response");
        let status = download_response.status();
        let headers = download_response.headers().clone();
        let bytes = to_bytes(download_response.into_body(), usize::MAX)
            .await
            .expect("body bytes");
        assert_eq!(
            status,
            StatusCode::OK,
            "download failed: {}",
            String::from_utf8_lossy(&bytes)
        );
        assert_eq!(
            headers
                .get(header::CONTENT_DISPOSITION)
                .and_then(|value| value.to_str().ok()),
            Some("attachment; filename=\"Bao_cao_tong_ket-2026.bin\"")
        );
        assert_eq!(bytes.as_ref(), plaintext);
    }

    #[tokio::test]
    async fn superior_sync_receives_updated_descendant_document_delta() {
        let harness = test_harness(NetworkMode::InternetTest);
        let initial_updated_at = "2026-04-23T10:00:00+00:00".to_owned();
        {
            let mut data = harness.state.data.write().await;
            data.organizations = vec![
                Organization {
                    id: "org-root".to_owned(),
                    parent_id: None,
                    name: "Root".to_owned(),
                    tier: 1,
                    category: "cap 1".to_owned(),
                    active: true,
                    created_at: now_string(),
                    updated_at: now_string(),
                },
                Organization {
                    id: "org-child".to_owned(),
                    parent_id: Some("org-root".to_owned()),
                    name: "Child".to_owned(),
                    tier: 2,
                    category: "cap 2".to_owned(),
                    active: true,
                    created_at: now_string(),
                    updated_at: now_string(),
                },
            ];
            data.users.push(User {
                id: "user-manager-root".to_owned(),
                username: "manager_root".to_owned(),
                password_hash: hash_password("Manager@123").expect("hash"),
                role: UserRole::OrgManager,
                org_id: Some("org-root".to_owned()),
                tree_key_enabled: false,
                active: true,
                created_at: now_string(),
            });
            data.documents.push(Document {
                id: "doc-shared".to_owned(),
                org_id: "org-child".to_owned(),
                title: "Tai lieu dong nhat".to_owned(),
                file_name: "dong-nhat.txt".to_owned(),
                mime_type: "text/plain".to_owned(),
                preview_text: "ban dau".to_owned(),
                year: 2026,
                encrypted_path: "runtime/data/doc-shared.bin".to_owned(),
                kem_ciphertext_b64: "cipher".to_owned(),
                nonce_b64: "nonce".to_owned(),
                uploaded_at: initial_updated_at.clone(),
                updated_at: initial_updated_at.clone(),
            });
        }

        let app = build_router(harness.state.clone());
        let sync_key_b64 = STANDARD.encode([9_u8; 32]);
        let (session_id, _) = login_and_get_session_with_sync_key(
            &app,
            &harness.state,
            "manager_root",
            "Manager%40123",
        )
        .await;
        let session_cookie = cookie_header(&session_id);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/sync/bootstrap")
                    .header(header::COOKIE, &session_cookie)
                    .header("x-browser-sync-key", &sync_key_b64)
                    .header("x-requested-with", "XMLHttpRequest")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body bytes");
        let envelope: EncryptedSyncEnvelope = serde_json::from_slice(&body).expect("sync envelope");
        let payload_bytes =
            decrypt_transport_payload(&sync_key_b64, &envelope.nonce_b64, &envelope.ciphertext_b64)
                .expect("decrypt payload");
        let payload: SyncPayload = serde_json::from_slice(&payload_bytes).expect("sync payload");
        assert_eq!(payload.snapshot.documents.len(), 1);
        assert_eq!(payload.snapshot.documents[0].preview_text, "ban dau");

        {
            let mut data = harness.state.data.write().await;
            let document = data
                .documents
                .iter_mut()
                .find(|item| item.id == "doc-shared")
                .expect("document");
            document.preview_text = "da cap nhat tu cap duoi".to_owned();
            document.updated_at = "2026-04-23T11:00:00+00:00".to_owned();
        }

        let delta_response = app
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/sync/bootstrap?since={}",
                        encode_form_value(&initial_updated_at)
                    ))
                    .header(header::COOKIE, &session_cookie)
                    .header("x-browser-sync-key", &sync_key_b64)
                    .header("x-requested-with", "XMLHttpRequest")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(delta_response.status(), StatusCode::OK);
        let delta_body = to_bytes(delta_response.into_body(), usize::MAX)
            .await
            .expect("delta bytes");
        let delta_envelope: EncryptedSyncEnvelope =
            serde_json::from_slice(&delta_body).expect("delta envelope");
        let delta_payload_bytes = decrypt_transport_payload(
            &sync_key_b64,
            &delta_envelope.nonce_b64,
            &delta_envelope.ciphertext_b64,
        )
        .expect("decrypt delta payload");
        let delta_payload: SyncPayload =
            serde_json::from_slice(&delta_payload_bytes).expect("delta payload");
        assert!(!delta_payload.full_sync);
        assert_eq!(delta_payload.snapshot.documents.len(), 1);
        assert_eq!(
            delta_payload.snapshot.documents[0].preview_text,
            "da cap nhat tu cap duoi"
        );
        assert_eq!(delta_payload.snapshot.documents[0].org_id, "org-child");
    }

    #[test]
    fn effective_shared_documents_only_originates_from_leaf_c_units() {
        let organizations = vec![
            Organization {
                id: "org-f".to_owned(),
                parent_id: None,
                name: "f".to_owned(),
                tier: 0,
                category: "cap 0".to_owned(),
                active: true,
                created_at: now_string(),
                updated_at: now_string(),
            },
            Organization {
                id: "org-e".to_owned(),
                parent_id: Some("org-f".to_owned()),
                name: "e1".to_owned(),
                tier: 1,
                category: "cap 1".to_owned(),
                active: true,
                created_at: now_string(),
                updated_at: now_string(),
            },
            Organization {
                id: "org-d".to_owned(),
                parent_id: Some("org-e".to_owned()),
                name: "d1".to_owned(),
                tier: 2,
                category: "cap 2".to_owned(),
                active: true,
                created_at: now_string(),
                updated_at: now_string(),
            },
            Organization {
                id: "org-c1".to_owned(),
                parent_id: Some("org-d".to_owned()),
                name: "c1".to_owned(),
                tier: 3,
                category: "cap 3".to_owned(),
                active: true,
                created_at: now_string(),
                updated_at: now_string(),
            },
            Organization {
                id: "org-c2".to_owned(),
                parent_id: Some("org-d".to_owned()),
                name: "c2".to_owned(),
                tier: 3,
                category: "cap 3".to_owned(),
                active: true,
                created_at: now_string(),
                updated_at: now_string(),
            },
        ];

        let documents = vec![
            Document {
                id: "doc-c1-1".to_owned(),
                org_id: "org-c1".to_owned(),
                title: "Tài liệu chung 1".to_owned(),
                file_name: "tai-lieu-chung-1.xlsx".to_owned(),
                mime_type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                    .to_owned(),
                preview_text: "Ho ten\nAn".to_owned(),
                year: 2026,
                encrypted_path: String::new(),
                kem_ciphertext_b64: String::new(),
                nonce_b64: String::new(),
                uploaded_at: "2026-04-20T10:00:00+00:00".to_owned(),
                updated_at: "2026-04-20T10:00:00+00:00".to_owned(),
            },
            Document {
                id: "doc-c1-2".to_owned(),
                org_id: "org-c1".to_owned(),
                title: "Tài liệu chung 2".to_owned(),
                file_name: "tai-lieu-chung-2.xlsx".to_owned(),
                mime_type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                    .to_owned(),
                preview_text: "Ho ten\nLan".to_owned(),
                year: 2026,
                encrypted_path: String::new(),
                kem_ciphertext_b64: String::new(),
                nonce_b64: String::new(),
                uploaded_at: "2026-04-20T10:01:00+00:00".to_owned(),
                updated_at: "2026-04-20T10:01:00+00:00".to_owned(),
            },
            Document {
                id: "doc-c2-1".to_owned(),
                org_id: "org-c2".to_owned(),
                title: "Tài liệu chung 1".to_owned(),
                file_name: "tai-lieu-chung-1.xlsx".to_owned(),
                mime_type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                    .to_owned(),
                preview_text: "Ho ten\nBinh".to_owned(),
                year: 2026,
                encrypted_path: String::new(),
                kem_ciphertext_b64: String::new(),
                nonce_b64: String::new(),
                uploaded_at: "2026-04-20T10:02:00+00:00".to_owned(),
                updated_at: "2026-04-20T10:02:00+00:00".to_owned(),
            },
            Document {
                id: "doc-c2-2".to_owned(),
                org_id: "org-c2".to_owned(),
                title: "Tài liệu chung 2".to_owned(),
                file_name: "tai-lieu-chung-2.xlsx".to_owned(),
                mime_type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                    .to_owned(),
                preview_text: "Ho ten\nMai".to_owned(),
                year: 2026,
                encrypted_path: String::new(),
                kem_ciphertext_b64: String::new(),
                nonce_b64: String::new(),
                uploaded_at: "2026-04-20T10:03:00+00:00".to_owned(),
                updated_at: "2026-04-20T10:03:00+00:00".to_owned(),
            },
        ];

        let c_docs = super::effective_shared_documents(&organizations, &documents, "org-c1");
        assert_eq!(c_docs.len(), 2);
        assert_eq!(c_docs[0].id, "doc-c1-1");

        let d_docs = super::effective_shared_documents(&organizations, &documents, "org-d");
        assert_eq!(d_docs.len(), 2);
        assert!(d_docs.iter().all(super::is_derived_shared_document));
        assert!(d_docs[0].preview_text.contains("An"));
        assert!(d_docs[0].preview_text.contains("Binh"));
        assert!(d_docs[1].preview_text.contains("Lan"));
        assert!(d_docs[1].preview_text.contains("Mai"));

        let e_docs = super::effective_shared_documents(&organizations, &documents, "org-e");
        assert_eq!(e_docs.len(), 2);
        assert!(e_docs.iter().all(super::is_derived_shared_document));
        assert_eq!(e_docs[0].preview_text, d_docs[0].preview_text);
        assert_eq!(e_docs[1].preview_text, d_docs[1].preview_text);

        let f_docs = super::effective_shared_documents(&organizations, &documents, "org-f");
        assert_eq!(f_docs.len(), 2);
        assert!(f_docs.iter().all(super::is_derived_shared_document));
        assert_eq!(f_docs[0].preview_text, e_docs[0].preview_text);
        assert_eq!(f_docs[1].preview_text, e_docs[1].preview_text);
    }

    #[test]
    fn aggregate_keeps_single_header_when_children_have_title_rows() {
        let make_doc = |id: &str, org: &str, body_name: &str| super::Document {
            id: id.to_owned(),
            org_id: org.to_owned(),
            title: org.to_owned(),
            file_name: format!("{org}.xlsx"),
            mime_type: "text/plain".to_owned(),
            preview_text: format!(
                "DANH SACH {org}\nSTT\tHo ten\tCap bac\n1\t{body_name}\tCap uy"
            ),
            year: 2026,
            encrypted_path: String::new(),
            kem_ciphertext_b64: String::new(),
            nonce_b64: String::new(),
            uploaded_at: "2026-01-01".to_owned(),
            updated_at: "2026-01-01".to_owned(),
        };
        let slot_docs = vec![
            ("c1".to_owned(), make_doc("d1", "c1", "Nguyen Van A")),
            ("c2".to_owned(), make_doc("d2", "c2", "Tran Thi B")),
            ("c3".to_owned(), make_doc("d3", "c3", "Le Van C")),
        ];

        let aggregated = super::aggregate_shared_slot_preview(&slot_docs, "Theo đơn vị");
        let rows = super::parse_preview_rows(&aggregated);

        // Đúng 1 dòng tiêu đề ở trên cùng + 3 dòng dữ liệu, không còn tựa đề/ tiêu đề lặp.
        let header_count = rows.iter().filter(|row| super::looks_like_header_row(row)).count();
        assert_eq!(header_count, 1, "phải chỉ còn 1 dòng tiêu đề: {rows:?}");
        assert_eq!(rows.len(), 4, "1 tiêu đề + 3 dữ liệu: {rows:?}");
        assert!(super::looks_like_header_row(&rows[0]));
        assert_eq!(rows[1][0], "1");
        assert_eq!(rows[2][0], "2");
        assert_eq!(rows[3][0], "3");
        assert!(!aggregated.contains("DANH SACH"), "tựa đề con phải bị loại bỏ");
    }
}

fn render_org_tree_svg(organizations: &[Organization], user: &User) -> Markup {
    let min_tier = organizations.iter().map(|org| org.tier).min().unwrap_or(0);
    let max_visible_tier = min_tier.saturating_add(2);
    let visible_organizations: Vec<_> = organizations
        .iter()
        .filter(|org| org.tier <= max_visible_tier)
        .cloned()
        .collect();
    let Some(layout) = build_tree_layout(&visible_organizations) else {
        return html! { div class="tree-canvas" {} };
    };
    let highlight_mode = tree_highlight_mode(&visible_organizations, user);

    html! {
        div class="tree-canvas" data-tree-min-tier=(min_tier) data-tree-max-tier=(max_visible_tier) data-tree-rendered-count=(visible_organizations.len()) {
            div class="tree-edit-sidebar" data-tree-edit-sidebar="true" hidden {
                button type="button" class="tree-edit-sidebar-close" data-tree-edit-close="true" title="Đóng" aria-label="Đóng thanh chỉnh sửa" { "×" }
                button type="button" class="tree-edit-sidebar-btn" data-tree-undo="true" title="Hoàn tác" aria-label="Hoàn tác" { "↶" }
                button type="button" class="tree-edit-sidebar-btn" data-tree-forward="true" title="Làm lại" aria-label="Làm lại" { "↷" }
                button type="button" class="tree-edit-sidebar-btn" data-tree-save="true" title="Lưu lại" aria-label="Lưu lại" {
                    svg viewBox="0 0 24 24" aria-hidden="true" {
                        path d="M5 3h11.2L21 7.8V19a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2Zm1.8 2v4.9h8.4V5H6.8Zm5.2 0v3H8.9V5H12Zm-5.2 9.2V19h10.4v-4.8H6.8Z";
                    }
                }
            }
            div class="tree-viewport" data-tree-viewport="true" data-tree-initial-scale={(format!("{:.3}", layout.initial_scale))} {
                svg viewBox={(format!("0 0 {:.0} {:.0}", layout.viewbox_width, layout.viewbox_height))} class="org-svg" role="img" aria-label="Cây tổ chức nội bộ" {
                    g id="tree-panzoom" {
                        @for edge in &layout.edges {
                            line
                                class={(if is_highlighted_edge(edge, &highlight_mode) { "tree-edge highlighted" } else { "tree-edge" })}
                                data-from-id=(&edge.from_id)
                                data-to-id=(&edge.to_id)
                                x1=(edge.x1)
                                y1=(edge.y1)
                                x2=(edge.x2)
                                y2=(edge.y2) {}
                        }
                        @for node in &layout.nodes {
                            (render_tree_node(
                                &node.org,
                                &node.display_label,
                                user,
                                node.x,
                                node.y,
                                node.org.tier.saturating_sub(min_tier),
                                is_highlighted_node(&node.org.id, &highlight_mode),
                            ))
                        }
                    }
                }
            }
            div class="tree-user-card" data-tree-user-card="true" hidden {
                input type="text" data-tree-user-username="true" placeholder="Tài khoản" class="tree-user-input";
                input type="text" data-tree-user-password="true" placeholder="Mật khẩu" class="tree-user-input";
            }
            div class="tree-rename-card" data-tree-rename-card="true" hidden {
                div class="tree-rename-row" {
                    input type="text" data-tree-rename-input="true" placeholder="Tên nút" class="tree-user-input tree-rename-input";
                    button type="button" class="tree-rename-save" data-tree-rename-save="true" aria-label="Lưu tên" title="Lưu tên" {
                        svg viewBox="0 0 24 24" width="16" height="16" aria-hidden="true" {
                            path d="M5 3.75A1.75 1.75 0 0 1 6.75 2h8.19c.46 0 .9.18 1.24.51l2.31 2.31c.33.33.51.78.51 1.24v12.19A1.75 1.75 0 0 1 17.25 20H6.75A1.75 1.75 0 0 1 5 18.25V3.75Zm2.75-.25a.25.25 0 0 0-.25.25v2.5c0 .41.34.75.75.75h7.5a.75.75 0 0 0 .75-.75V5.06a.25.25 0 0 0-.07-.18l-1.31-1.31a.25.25 0 0 0-.18-.07H7.75ZM8 11.75c0-.41.34-.75.75-.75h6.5c.41 0 .75.34.75.75v4.5a.75.75 0 0 1-.75.75h-6.5a.75.75 0 0 1-.75-.75v-4.5Z";
                        }
                    }
                }
            }
        }
    }
}

#[derive(Clone)]
struct TreeNodeLayout {
    org: Organization,
    x: f32,
    y: f32,
    display_label: String,
}

#[derive(Clone)]
struct TreeEdgeLayout {
    from_id: String,
    to_id: String,
    x1: f32,
    y1: f32,
    x2: f32,
    y2: f32,
}

enum TreeHighlightMode {
    None,
    RootBranches {
        root_id: String,
        highlighted_ids: HashSet<String>,
    },
    Subtree {
        highlighted_ids: HashSet<String>,
    },
}

struct TreeLayout {
    viewbox_width: f32,
    viewbox_height: f32,
    initial_scale: f32,
    nodes: Vec<TreeNodeLayout>,
    edges: Vec<TreeEdgeLayout>,
}

#[derive(Serialize)]
struct DashboardTreeUserRecord {
    username: String,
    password: String,
}

fn build_tree_layout(organizations: &[Organization]) -> Option<TreeLayout> {
    let org_ids: HashSet<_> = organizations.iter().map(|org| org.id.as_str()).collect();
    let mut roots: Vec<_> = organizations
        .iter()
        .filter(|org| {
            org.parent_id
                .as_deref()
                .map(|parent_id| !org_ids.contains(parent_id))
                .unwrap_or(true)
        })
        .cloned()
        .collect();
    if roots.is_empty() {
        let min_tier = organizations.iter().map(|org| org.tier).min()?;
        roots = organizations
            .iter()
            .filter(|org| org.tier == min_tier)
            .cloned()
            .collect();
    }
    roots.sort_by(|left, right| org_sort_key(&left.name).cmp(&org_sort_key(&right.name)));

    let mut children_by_parent: HashMap<String, Vec<Organization>> = HashMap::new();
    for org in organizations {
        if let Some(parent_id) = org.parent_id.as_deref()
            && org_ids.contains(parent_id)
        {
            children_by_parent
                .entry(parent_id.to_owned())
                .or_default()
                .push(org.clone());
        }
    }
    for children in children_by_parent.values_mut() {
        children.sort_by(|left, right| org_sort_key(&left.name).cmp(&org_sort_key(&right.name)));
    }

    let mut levels: Vec<Vec<Organization>> = Vec::new();
    let mut current_level = roots;
    let mut visited: HashSet<String> = HashSet::new();
    while !current_level.is_empty() {
        let mut next_level = Vec::new();
        let mut visible_level = Vec::new();
        for org in current_level {
            if !visited.insert(org.id.clone()) {
                continue;
            }
            if let Some(children) = children_by_parent.get(&org.id) {
                next_level.extend(children.iter().cloned());
            }
            visible_level.push(org);
        }
        if !visible_level.is_empty() {
            levels.push(visible_level);
        }
        current_level = next_level;
    }

    let mut visual_rows: Vec<Vec<Organization>> = Vec::new();
    for level in levels {
        if level.len() > 12 {
            let split_at = level.len().div_ceil(2);
            visual_rows.push(level[..split_at].to_vec());
            visual_rows.push(level[split_at..].to_vec());
        } else {
            visual_rows.push(level);
        }
    }

    let max_width = visual_rows
        .iter()
        .map(|level| level.len())
        .max()
        .unwrap_or(1);
    let horizontal_gap = 172.0_f32;
    let vertical_gap = 158.0_f32;
    let margin_x = 150.0_f32;
    let margin_y = 130.0_f32;
    let viewbox_width = ((max_width as f32 - 1.0).max(0.0) * horizontal_gap + margin_x * 2.0)
        .max(900.0)
        .ceil();
    let viewbox_height = ((visual_rows.len() as f32 - 1.0).max(0.0) * vertical_gap
        + margin_y * 2.0)
        .max(640.0)
        .ceil();
    let center_x = viewbox_width / 2.0;

    let mut nodes = Vec::new();
    let mut positions: HashMap<String, (f32, f32)> = HashMap::new();
    for (level_index, level) in visual_rows.iter().enumerate() {
        let row_width = (level.len() as f32 - 1.0).max(0.0) * horizontal_gap;
        let start_x = center_x - row_width / 2.0;
        let y = margin_y + level_index as f32 * vertical_gap;
        for (index, org) in level.iter().enumerate() {
            let x = start_x + index as f32 * horizontal_gap;
            positions.insert(org.id.clone(), (x, y));
            nodes.push(TreeNodeLayout {
                org: org.clone(),
                x,
                y,
                display_label: unit_display_label(&org.name),
            });
        }
    }

    let mut edges = Vec::new();
    for org in organizations {
        let Some(parent_id) = org.parent_id.as_deref() else {
            continue;
        };
        let (Some((parent_x, parent_y)), Some((child_x, child_y))) =
            (positions.get(parent_id), positions.get(&org.id))
        else {
            continue;
        };
        let (x1, y1, x2, y2) = edge_points(
            *parent_x,
            *parent_y,
            node_radius(org.tier.saturating_sub(1)) as f32 - 8.0,
            *child_x,
            *child_y,
            node_radius(org.tier) as f32 - 8.0,
        );
        edges.push(TreeEdgeLayout {
            from_id: parent_id.to_owned(),
            to_id: org.id.clone(),
            x1,
            y1,
            x2,
            y2,
        });
    }

    Some(TreeLayout {
        viewbox_width,
        viewbox_height,
        initial_scale: 0.88,
        nodes,
        edges,
    })
}

fn unit_display_label(name: &str) -> String {
    let trimmed = name.trim();
    if trimmed.is_empty() || trimmed.to_lowercase().starts_with("đơn vị ") {
        trimmed.to_owned()
    } else {
        format!("Đơn vị {trimmed}")
    }
}

fn node_radius(tier: u32) -> u32 {
    match tier {
        0 => 100,
        1 => 68,
        2 => 50,
        3 => 40,
        _ => 30,
    }
}

fn node_box_size(tier: u32) -> (u32, u32, u32) {
    match tier {
        0 => (220, 86, 16),
        1 => (158, 64, 14),
        2 => (132, 54, 12),
        3 => (108, 46, 10),
        _ => (78, 34, 8),
    }
}

fn tree_highlight_mode(organizations: &[Organization], user: &User) -> TreeHighlightMode {
    let Some(root) = organizations.iter().find(|org| org.tier == 0) else {
        return TreeHighlightMode::None;
    };

    if user.role == UserRole::RootAdmin {
        let highlighted_ids = direct_children(organizations, &root.id)
            .into_iter()
            .map(|org| org.id)
            .collect();
        return TreeHighlightMode::RootBranches {
            root_id: root.id.clone(),
            highlighted_ids,
        };
    }

    let Some(user_org_id) = user.org_id.as_deref() else {
        return TreeHighlightMode::None;
    };
    let Some(current_org) = organizations.iter().find(|org| org.id == user_org_id) else {
        return TreeHighlightMode::None;
    };

    if current_org.tier == 0 {
        let highlighted_ids = direct_children(organizations, &root.id)
            .into_iter()
            .map(|org| org.id)
            .collect();
        return TreeHighlightMode::RootBranches {
            root_id: root.id.clone(),
            highlighted_ids,
        };
    }

    if current_org.tier <= 3 {
        let mut highlighted_ids = descendant_ids(organizations, user_org_id);
        highlighted_ids.insert(user_org_id.to_owned());
        return TreeHighlightMode::Subtree { highlighted_ids };
    }

    TreeHighlightMode::None
}

fn is_highlighted_node(org_id: &str, mode: &TreeHighlightMode) -> bool {
    match mode {
        TreeHighlightMode::None => false,
        TreeHighlightMode::RootBranches {
            highlighted_ids, ..
        } => highlighted_ids.contains(org_id),
        TreeHighlightMode::Subtree { highlighted_ids } => highlighted_ids.contains(org_id),
    }
}

fn is_highlighted_edge(edge: &TreeEdgeLayout, mode: &TreeHighlightMode) -> bool {
    match mode {
        TreeHighlightMode::None => false,
        TreeHighlightMode::RootBranches {
            root_id,
            highlighted_ids,
        } => edge.from_id == *root_id && highlighted_ids.contains(&edge.to_id),
        TreeHighlightMode::Subtree { highlighted_ids } => {
            highlighted_ids.contains(&edge.from_id) && highlighted_ids.contains(&edge.to_id)
        }
    }
}

fn render_tree_node(
    org: &Organization,
    display_label: &str,
    user: &User,
    x: f32,
    y: f32,
    visible_generation: u32,
    highlighted: bool,
) -> Markup {
    let mut node_class = String::from("tree-node");
    if highlighted {
        node_class.push_str(" highlighted");
    }
    if is_current_user_org(user, org) {
        node_class.push_str(" current");
    }
    let (node_width, node_height, node_radius) = node_box_size(org.tier);
    let node_x = -(node_width as i32) / 2;
    let node_y = -(node_height as i32) / 2;

    html! {
        a href={(format!("/units/{}?return_to=%2F", org.id))} class={(format!("tree-node-link tier-{} generation-{}", org.tier, visible_generation))} data-org-id=(&org.id) {
            g class={(format!("tree-node-group tier-{} generation-{}", org.tier, visible_generation))} data-org-id=(&org.id) transform={(format!("translate({x} {y})"))} {
                rect class=(node_class) x=(node_x) y=(node_y) width=(node_width) height=(node_height) rx=(node_radius) ry=(node_radius) {}
                text class="tree-node-text" text-anchor="middle" dominant-baseline="middle" { (display_label) }
            }
        }
    }
}

fn is_current_user_org(user: &User, org: &Organization) -> bool {
    user.org_id.as_deref() == Some(org.id.as_str())
}

fn document_view_policy(
    user: &User,
    target_org_id: &str,
    data: &AppData,
    _session: Option<&SessionState>,
) -> DocumentViewPolicy {
    if user.role == UserRole::RootAdmin {
        return DocumentViewPolicy {
            branch_requires_password: false,
            can_view_branch: true,
            can_view_unit: true,
        };
    }

    let Some(user_org_id) = user.org_id.as_deref() else {
        return DocumentViewPolicy {
            branch_requires_password: false,
            can_view_branch: false,
            can_view_unit: false,
        };
    };

    if user_org_id == target_org_id {
        return DocumentViewPolicy {
            branch_requires_password: false,
            can_view_branch: true,
            can_view_unit: true,
        };
    }

    if descendant_ids(&data.organizations, user_org_id).contains(target_org_id) {
        return DocumentViewPolicy {
            branch_requires_password: false,
            can_view_branch: true,
            can_view_unit: true,
        };
    }

    if ancestor_ids(&data.organizations, user_org_id).contains(target_org_id) {
        return DocumentViewPolicy {
            branch_requires_password: false,
            can_view_branch: true,
            can_view_unit: true,
        };
    }

    DocumentViewPolicy {
        branch_requires_password: false,
        can_view_branch: false,
        can_view_unit: false,
    }
}

fn profile_access(user: &User, target_org_id: &str, data: &AppData) -> Option<ProfileAccess> {
    if user.role == UserRole::RootAdmin {
        return Some(ProfileAccess::Full);
    }
    let user_org_id = user.org_id.as_deref()?;
    if user_org_id == target_org_id
        || descendant_ids(&data.organizations, user_org_id).contains(target_org_id)
    {
        return Some(ProfileAccess::Full);
    }
    if ancestor_ids(&data.organizations, user_org_id).contains(target_org_id) {
        return Some(ProfileAccess::Limited);
    }
    None
}

fn tree_visible_ids(user: &User, data: &AppData) -> HashSet<String> {
    if user.role == UserRole::RootAdmin {
        return data
            .organizations
            .iter()
            .map(|org| org.id.clone())
            .collect();
    }
    let Some(org_id) = user.org_id.as_deref() else {
        return HashSet::new();
    };
    let mut ids = descendant_ids(&data.organizations, org_id);
    ids.extend(ancestor_ids(&data.organizations, org_id));
    ids
}

fn dashboard_graph_organizations(user: &User, organizations: &[Organization]) -> Vec<Organization> {
    let root_org = if user.role == UserRole::RootAdmin {
        organizations.iter().find(|org| org.tier == 0)
    } else {
        user.org_id
            .as_deref()
            .and_then(|org_id| organizations.iter().find(|org| org.id == org_id))
    };
    let Some(root_org) = root_org else {
        return Vec::new();
    };

    let org_by_id: HashMap<&str, &Organization> = organizations
        .iter()
        .map(|org| (org.id.as_str(), org))
        .collect();
    let mut visible_ids = HashSet::from([root_org.id.clone()]);
    let mut frontier = vec![root_org.id.clone()];
    for _ in 0..2 {
        let mut next_frontier = Vec::new();
        for parent_id in &frontier {
            let mut children: Vec<_> = organizations
                .iter()
                .filter(|org| org.parent_id.as_deref() == Some(parent_id.as_str()))
                .collect();
            children.sort_by_key(|org| (org.tier, org_sort_key(&org.name)));
            let child_limit = 3;
            for child in children.into_iter().take(child_limit) {
                if visible_ids.insert(child.id.clone()) {
                    next_frontier.push(child.id.clone());
                }
            }
        }
        frontier = next_frontier;
    }
    let mut visible_tree: Vec<_> = visible_ids
        .iter()
        .filter_map(|id| org_by_id.get(id.as_str()).copied().cloned())
        .collect();
    visible_tree.sort_by_key(|org| (org.tier, org_sort_key(&org.name)));
    visible_tree
}

fn unescape_preview_cell(value: &str) -> String {
    let mut output = String::new();
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            output.push(ch);
            continue;
        }
        match chars.next() {
            Some('n') => output.push('\n'),
            Some('t') => output.push('\t'),
            Some('r') => output.push('\r'),
            Some('\\') => output.push('\\'),
            Some(next) => {
                output.push('\\');
                output.push(next);
            }
            None => output.push('\\'),
        }
    }
    output
}

fn escape_preview_cell(value: &str) -> String {
    let normalized = value.replace("\r\n", "\n").replace('\r', "\n");
    let mut output = String::new();
    for ch in normalized.chars() {
        match ch {
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\t' => output.push_str("\\t"),
            _ => output.push(ch),
        }
    }
    output
}

fn parse_preview_rows(preview: &str) -> Vec<Vec<String>> {
    let normalized = preview.replace("\r\n", "\n").replace('\r', "\n");
    let delimiter = if normalized.contains('\t') {
        '\t'
    } else if normalized.contains(';') {
        ';'
    } else {
        ','
    };
    normalized
        .lines()
        .map(|line| {
            line.split(delimiter)
                .map(|cell| unescape_preview_cell(cell.trim()))
                .collect::<Vec<_>>()
        })
        .filter(|row| !row.is_empty() && row.iter().any(|cell| !cell.is_empty()))
        .collect()
}

fn serialize_preview_rows(rows: &[Vec<String>]) -> String {
    rows.iter()
        .map(|row| {
            row.iter()
                .map(|cell| escape_preview_cell(cell))
                .collect::<Vec<_>>()
                .join("\t")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn collapse_unit_activity_column(rows: &mut [Vec<String>]) {
    let Some(header) = rows.first() else {
        return;
    };
    let Some(activity_col) = header.iter().position(|value| {
        normalize_header_key(value) == normalize_header_key("Hoạt động của đơn vị")
    }) else {
        return;
    };

    let mut seen = HashSet::new();
    let mut activities = Vec::new();
    for row in rows.iter().skip(1) {
        let Some(cell) = row.get(activity_col) else {
            continue;
        };
        for activity in cell.lines().map(str::trim).filter(|line| !line.is_empty()) {
            if seen.insert(activity.to_owned()) {
                activities.push(activity.to_owned());
            }
        }
    }
    if activities.is_empty() {
        return;
    }
    for (index, row) in rows.iter_mut().skip(1).enumerate() {
        if let Some(cell) = row.get_mut(activity_col) {
            *cell = if index == 0 {
                activities.join("\n")
            } else {
                String::new()
            };
        }
    }
}

fn normalize_header_key(value: &str) -> String {
    value
        .trim()
        .to_lowercase()
        .replace("đ", "d")
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect()
}

fn renumber_stt_column(rows: &mut [Vec<String>]) {
    let Some(header) = rows.first() else {
        return;
    };
    let first_header = header
        .first()
        .map(|value| normalize_header_key(value))
        .unwrap_or_default();
    if first_header != "stt" && first_header != "sothutu" {
        return;
    }
    for (index, row) in rows.iter_mut().skip(1).enumerate() {
        if let Some(cell) = row.first_mut() {
            *cell = (index + 1).to_string();
        }
    }
}

fn extract_age_value(row: &[String]) -> i32 {
    let joined = row.join(" ");
    let mut best = 999;
    for token in joined.split(|ch: char| !ch.is_ascii_digit()) {
        if token.is_empty() {
            continue;
        }
        if let Ok(value) = token.parse::<i32>()
            && (18..=90).contains(&value)
        {
            best = best.min(value);
        }
    }
    best
}

/// Các từ khóa nhận diện dòng tiêu đề cột trong một bảng danh sách.
const HEADER_ROW_KEYWORDS: &[&str] = &[
    "stt",
    "sothutu",
    "hoten",
    "hovaten",
    "ngaysinh",
    "sinhngay",
    "namsinh",
    "trinhdo",
    "capbac",
    "chucvu",
    "hoatdongcuadonvi",
    "mucdohoanthanhnhiemvu",
    "diachi",
    "sodienthoai",
    "ngayvaotochuc",
    "donvi",
    "quequan",
];

/// Một dòng được coi là dòng tiêu đề nếu có từ 2 ô trở lên khớp với từ khóa tiêu đề.
/// Ngưỡng 2 ô giúp tránh nhầm dòng dữ liệu (ví dụ ô tên người) thành tiêu đề.
fn looks_like_header_row(row: &[String]) -> bool {
    row.iter()
        .filter(|cell| {
            let key = normalize_header_key(cell);
            !key.is_empty() && HEADER_ROW_KEYWORDS.contains(&key.as_str())
        })
        .count()
        >= 2
}

fn aggregate_shared_slot_preview(slot_docs: &[(String, Document)], method: &str) -> String {
    let canonical = method.trim().to_ascii_lowercase();

    // Gom dữ liệu từ nhiều đơn vị con: chỉ giữ DUY NHẤT một dòng tiêu đề ở trên cùng.
    // Mỗi tài liệu con có thể có dòng tựa đề phía trên dòng tiêu đề cột; ta dò đúng
    // dòng tiêu đề theo nội dung, bỏ phần tựa đề và mọi dòng tiêu đề bị lặp lại.
    let mut header: Option<Vec<String>> = None;
    let mut body_rows: Vec<Vec<String>> = Vec::new();
    for (_, document) in slot_docs {
        let rows = parse_preview_rows(&document.preview_text);
        if rows.is_empty() {
            continue;
        }
        match rows.iter().position(|row| looks_like_header_row(row)) {
            Some(header_idx) => {
                if header.is_none() {
                    header = Some(rows[header_idx].clone());
                }
                for (index, row) in rows.into_iter().enumerate() {
                    // Bỏ phần tựa đề (đứng trước tiêu đề), bỏ chính dòng tiêu đề,
                    // và bỏ mọi dòng tiêu đề lặp lại nằm trong phần thân.
                    if index <= header_idx || looks_like_header_row(&row) {
                        continue;
                    }
                    body_rows.push(row);
                }
            }
            None => {
                // Không dò được tiêu đề: coi dòng đầu là tiêu đề (giữ hành vi cũ).
                if header.is_none() {
                    header = rows.first().cloned();
                }
                body_rows.extend(rows.into_iter().skip(1));
            }
        }
    }

    if canonical.contains("a-z") || canonical.contains("tên") {
        body_rows.sort_by(|left, right| {
            let left_key = left.first().cloned().unwrap_or_default().to_ascii_lowercase();
            let right_key = right
                .first()
                .cloned()
                .unwrap_or_default()
                .to_ascii_lowercase();
            left_key.cmp(&right_key)
        });
    } else if canonical.contains("độ tuổi") || canonical.contains("tuoi") {
        body_rows.sort_by_key(|row| extract_age_value(row));
    }

    let mut merged = Vec::new();
    if let Some(head) = header {
        merged.push(head);
    }
    merged.extend(body_rows);
    renumber_stt_column(&mut merged);
    collapse_unit_activity_column(&mut merged);
    serialize_preview_rows(&merged)
}

const DERIVED_SHARED_DOCUMENT_PREFIX: &str = "derived-shared::";

fn is_derived_shared_document(document: &Document) -> bool {
    document.id.starts_with(DERIVED_SHARED_DOCUMENT_PREFIX)
}

fn derived_shared_document_slot(doc_id: &str, unit_id: &str) -> Option<usize> {
    let payload = doc_id.strip_prefix(DERIVED_SHARED_DOCUMENT_PREFIX)?;
    let (derived_unit_id, slot) = payload.rsplit_once(':')?;
    if derived_unit_id != unit_id {
        return None;
    }
    slot.parse::<usize>().ok()
}

fn sorted_real_shared_documents(documents: &[Document], org_id: &str) -> Vec<Document> {
    let mut shared_docs: Vec<_> = documents
        .iter()
        .filter(|item| {
            item.org_id == org_id && is_shared_document(item) && !is_derived_shared_document(item)
        })
        .cloned()
        .collect();
    shared_docs.sort_by(|left, right| {
        left.uploaded_at
            .cmp(&right.uploaded_at)
            .then_with(|| left.file_name.cmp(&right.file_name))
    });
    shared_docs
}

fn latest_local_list_document(documents: &[Document], org: &Organization) -> Option<Document> {
    let expected_file_name = format!("{}.xlxs", org.name);
    documents
        .iter()
        .filter(|item| {
            item.org_id == org.id
                && !is_shared_document(item)
                && !is_legacy_demo_document(item)
                && (item.file_name == expected_file_name
                    || item.file_name.ends_with(".xlsx")
                    || item.file_name.ends_with(".xlxs"))
        })
        .max_by(|left, right| {
            left.updated_at
                .cmp(&right.updated_at)
                .then_with(|| left.uploaded_at.cmp(&right.uploaded_at))
                .then_with(|| left.file_name.cmp(&right.file_name))
        })
        .cloned()
}

fn build_derived_shared_document(
    unit_name: &str,
    unit_id: &str,
    slot_idx: usize,
    slot_docs: &[(String, Document)],
) -> Document {
    let preview_text = aggregate_shared_slot_preview(slot_docs, "Theo đơn vị");
    let updated_at = slot_docs
        .iter()
        .map(|(_, document)| document.updated_at.as_str())
        .max()
        .unwrap_or_default()
        .to_owned();
    let year = slot_docs
        .iter()
        .map(|(_, document)| document.year)
        .max()
        .unwrap_or_else(|| Utc::now().year());
    Document {
        id: format!(
            "{}{unit_id}:{}",
            DERIVED_SHARED_DOCUMENT_PREFIX,
            slot_idx + 1
        ),
        org_id: unit_id.to_owned(),
        title: unit_name.to_owned(),
        file_name: format!("{unit_name}.xlsx"),
        mime_type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet".to_owned(),
        preview_text,
        year,
        encrypted_path: String::new(),
        kem_ciphertext_b64: String::new(),
        nonce_b64: String::new(),
        uploaded_at: updated_at.clone(),
        updated_at,
    }
}

fn effective_shared_documents_cached(
    organizations: &[Organization],
    documents: &[Document],
    org_id: &str,
    cache: &mut HashMap<String, Vec<Document>>,
) -> Vec<Document> {
    if let Some(cached) = cache.get(org_id) {
        return cached.clone();
    }

    let mut children = direct_children(organizations, org_id);
    children.sort_by(|left, right| org_sort_key(&left.name).cmp(&org_sort_key(&right.name)));

    let result = if children.is_empty() {
        let Some(org) = organizations.iter().find(|item| item.id == org_id) else {
            cache.insert(org_id.to_owned(), Vec::new());
            return Vec::new();
        };
        latest_local_list_document(documents, org)
            .map(|document| vec![document])
            .unwrap_or_else(|| sorted_real_shared_documents(documents, org_id))
    } else {
        let child_shared: Vec<_> = children
            .iter()
            .map(|child| {
                (
                    child.name.clone(),
                    effective_shared_documents_cached(organizations, documents, &child.id, cache),
                )
            })
            .collect();
        let max_slots = child_shared
            .iter()
            .map(|(_, docs)| docs.len())
            .max()
            .unwrap_or(0);

        let mut derived_docs = Vec::new();
        for slot_idx in 0..max_slots {
            let mut slot_docs = Vec::new();
            for (child_name, docs) in &child_shared {
                if let Some(document) = docs.get(slot_idx) {
                    slot_docs.push((child_name.clone(), document.clone()));
                }
            }
            if !slot_docs.is_empty() {
                let unit_name = organizations
                    .iter()
                    .find(|item| item.id == org_id)
                    .map(|item| item.name.as_str())
                    .unwrap_or("tong-hop");
                derived_docs.push(build_derived_shared_document(
                    unit_name, org_id, slot_idx, &slot_docs,
                ));
            }
        }
        derived_docs
    };

    cache.insert(org_id.to_owned(), result.clone());
    result
}

fn effective_shared_documents(
    organizations: &[Organization],
    documents: &[Document],
    org_id: &str,
) -> Vec<Document> {
    let mut cache = HashMap::new();
    effective_shared_documents_cached(organizations, documents, org_id, &mut cache)
}

fn build_member_sections(
    unit: &Organization,
    access: ProfileAccess,
    data: &AppData,
) -> Vec<MemberSection> {
    if access == ProfileAccess::Limited {
        return vec![MemberSection {
            unit: unit.clone(),
            members: limited_members_for_unit(&unit.id, data),
        }];
    }

    let mut sections = direct_children(&data.organizations, &unit.id);
    sections.sort_by(|left, right| org_sort_key(&left.name).cmp(&org_sort_key(&right.name)));
    if unit.tier <= 2 {
        sections.truncate(3);
    }
    if sections.is_empty() {
        sections.push(unit.clone());
    }

    sections
        .into_iter()
        .map(|section_unit| {
            let mut members: Vec<_> = data
                .members
                .iter()
                .filter(|member| member.org_id == section_unit.id)
                .cloned()
                .collect();
            members.sort_by(|left, right| left.full_name.cmp(&right.full_name));
            MemberSection {
                unit: section_unit,
                members,
            }
        })
        .collect()
}

fn limited_members_for_unit(unit_id: &str, data: &AppData) -> Vec<Member> {
    data.members
        .iter()
        .filter(|member| member.org_id == unit_id && member.is_key_member())
        .take(3)
        .cloned()
        .collect()
}

fn normalize_members(data: &mut AppData) -> usize {
    let org_names: HashMap<String, String> = data
        .organizations
        .iter()
        .map(|org| (org.id.clone(), org.name.clone()))
        .collect();
    let mut updated = 0;

    for (index, member) in data.members.iter_mut().enumerate() {
        let org_name = org_names
            .get(&member.org_id)
            .map(String::as_str)
            .unwrap_or("don-vi");
        let mut changed = false;

        if member.birth_date.is_empty() {
            member.birth_date = seed_birth_date(0, index % 5);
            changed = true;
        }
        if member.address.is_empty() {
            member.address = format!("Khu vực nội bộ {}", org_name.to_uppercase());
            changed = true;
        }
        if member.phone.is_empty() {
            member.phone = seed_phone(0, index % 5);
            changed = true;
        }
        if member.joined_at.is_empty() {
            member.joined_at = format!("{}-01-01", member.year);
            changed = true;
        }

        if changed {
            member.updated_at = now_string();
            updated += 1;
        }
    }

    updated
}

fn normalize_org_node_credentials(data: &mut AppData) -> anyhow::Result<usize> {
    let mut updated = 0;

    let mut usernames_in_use: HashMap<String, String> = HashMap::new();
    for user in &data.users {
        usernames_in_use.insert(user.username.clone(), user.id.clone());
    }

    for user in data.users.iter_mut() {
        if user.role == UserRole::RootAdmin && user.org_id.is_none() {
            let (default_username, default_password) = default_root_admin_credentials();
            let mut changed = false;
            if user.username.is_empty() || user.username == "0" {
                usernames_in_use.remove(&user.username);
                user.username = default_username.to_owned();
                usernames_in_use.insert(user.username.clone(), user.id.clone());
                changed = true;
            }
            if user.password_hash.trim().is_empty() {
                user.password_hash = hash_password(default_password)?;
                changed = true;
            }
            if changed {
                updated += 1;
            }
            continue;
        }

        let Some(org_id) = user.org_id.as_ref() else {
            continue;
        };
        let Some((default_username, default_password)) =
            default_org_user_credentials(&data.organizations, org_id)
        else {
            continue;
        };
        let legacy_label = data
            .organizations
            .iter()
            .find(|org| org.id == *org_id)
            .map(|org| org.name.to_lowercase())
            .unwrap_or_default();

        let mut changed = false;

        let should_reset_username = user.username.is_empty()
            || user.username == legacy_label
            || user.username == default_username;
        if should_reset_username && user.username != default_username {
            let taken_by_other = usernames_in_use
                .get(&default_username)
                .map(|owner_id| owner_id != &user.id)
                .unwrap_or(false);
            if !taken_by_other {
                usernames_in_use.remove(&user.username);
                user.username = default_username.clone();
                usernames_in_use.insert(user.username.clone(), user.id.clone());
                changed = true;
            }
        }

        let should_reset_password = user.password_hash.trim().is_empty();
        if should_reset_password {
            user.password_hash = hash_password(&default_password)?;
            changed = true;
        }

        if changed {
            updated += 1;
        }
    }

    Ok(updated)
}

fn seed_birth_date(tier: u32, index: usize) -> String {
    format!(
        "{:04}-{:02}-{:02}",
        1982 + tier as i32 + index as i32,
        (index % 9) + 1,
        (index % 19) + 8
    )
}

fn seed_joined_at(tier: u32, index: usize) -> String {
    format!(
        "{:04}-{:02}-{:02}",
        2011 + tier as i32 + index as i32,
        (index % 10) + 1,
        (index % 17) + 10
    )
}

fn seed_phone(tier: u32, index: usize) -> String {
    format!(
        "09{}{:02}{:04}",
        tier,
        index + 10,
        (index * 137 + 2401) % 10000
    )
}

fn seed_address(org: &Organization, index: usize) -> String {
    format!("Cụm {} - tuyến {}", org.name.to_uppercase(), index + 1)
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn excel_cell_to_string(cell: &Data) -> String {
    match cell {
        Data::Empty => String::new(),
        Data::String(value) => value.trim().to_owned(),
        Data::Float(value) if value.fract() == 0.0 => format!("{value:.0}"),
        Data::Float(value) => value.to_string(),
        Data::Int(value) => value.to_string(),
        Data::Bool(value) => {
            if *value {
                "TRUE".to_owned()
            } else {
                "FALSE".to_owned()
            }
        }
        Data::DateTime(value) => value.to_string(),
        Data::DateTimeIso(value) | Data::DurationIso(value) => value.clone(),
        Data::Error(value) => value.to_string(),
    }
}

fn build_excel_document_preview(bytes: &[u8]) -> Option<String> {
    let cursor = Cursor::new(bytes.to_vec());
    let mut workbook = open_workbook_auto_from_rs(cursor).ok()?;
    let range = workbook.worksheet_range_at(0)?.ok()?;
    let rows = range
        .rows()
        .take(80)
        .map(|row| row.iter().map(excel_cell_to_string).collect::<Vec<_>>())
        .filter(|row| row.iter().any(|cell| !cell.trim().is_empty()))
        .collect::<Vec<_>>();
    if rows.is_empty() {
        None
    } else {
        Some(serialize_preview_rows(&rows))
    }
}

fn build_document_preview(bytes: &[u8], file_name: &str) -> String {
    let normalized_name = file_name.to_ascii_lowercase();
    if (normalized_name.ends_with(".xlsx") || normalized_name.ends_with(".xlxs"))
        && let Some(preview) = build_excel_document_preview(bytes)
    {
        return preview;
    }

    let preview = String::from_utf8_lossy(bytes).replace('\0', " ");
    let preview = preview.lines().take(28).collect::<Vec<_>>().join("\n");
    if preview.trim().is_empty() {
        format!("Xem nhanh không khả dụng cho {}.", file_name)
    } else {
        preview.chars().take(2800).collect()
    }
}

fn dashboard_script() -> &'static str {
    r#"
(() => {
    window.WebsiteBuuSync?.boot();
    const syncClient = window.WebsiteBuuSync || null;
    const clientUi = window.WebsiteBuuClientUi || {
        isOffline: () => navigator.onLine === false,
        requireOnline: () => navigator.onLine !== false,
        showNotice: () => {},
    };
    const encoder = new TextEncoder();
    const decoder = new TextDecoder();
    const bytesToBase64 = (bytes) => {
        let binary = '';
        bytes.forEach((value) => {
            binary += String.fromCharCode(value);
        });
        return btoa(binary);
    };
    const base64ToBytes = (value) => Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
    const panelRoots = Array.from(document.querySelectorAll('.panel-shell[data-panel], .overlay-panel[data-panel]'));
    const initialPanel = document.body?.getAttribute('data-initial-panel') || '';
    const clearPanelQueryState = () => {
        const url = new URL(window.location.href);
        const changed = url.searchParams.has('panel') || url.searchParams.has('chat');
        if (!changed) return;
        url.searchParams.delete('panel');
        url.searchParams.delete('chat');
        const nextUrl = `${url.pathname}${url.search}${url.hash}`;
        window.history.replaceState(window.history.state, '', nextUrl);
        document.body?.setAttribute('data-initial-panel', '');
    };
    const syncCompactPanels = () => {
        document.querySelectorAll('.panel-shell').forEach((panel) => {
            const compactPanel = Array.from(panel.children).find((child) => child.classList && child.classList.contains('compact-panel'));
            if (!compactPanel) return;
            compactPanel.style.setProperty('display', panel.classList.contains('is-open') ? 'grid' : 'none', 'important');
        });
    };
    const closePanels = (exceptName = null) => {
        panelRoots.forEach((panel) => {
            const name = panel.getAttribute('data-panel');
            panel.classList.toggle('is-open', !!exceptName && name === exceptName);
        });
        syncCompactPanels();
        document.querySelectorAll('[data-ip-section="true"].is-open').forEach((panel) => panel.classList.remove('is-open'));
        if (exceptName !== 'chat') {
            clearPanelQueryState();
        }
    };

    document.querySelectorAll('[data-panel-toggle]').forEach((button) => {
        button.addEventListener('click', (event) => {
            event.preventDefault();
            event.stopPropagation();
            if (button.getAttribute('data-requires-online') === 'true' && !clientUi.requireOnline()) {
                return;
            }
            const target = button.getAttribute('data-panel-toggle');
            const panel = document.querySelector(`.panel-shell[data-panel="${target}"], .overlay-panel[data-panel="${target}"]`);
            if (!panel) return;
            const shouldOpen = !panel.classList.contains('is-open');
            closePanels(shouldOpen ? target : null);
        });
    });

    document.addEventListener('click', (event) => {
        const inside = event.target.closest('.panel-shell, [data-panel-toggle]');
        if (!inside) closePanels();
    });

    if (initialPanel) {
        requestAnimationFrame(() => closePanels(initialPanel));
    }

    const dashboardCsrf = document.body?.getAttribute('data-tree-csrf') || '';
    const reportDataNode = document.getElementById('dashboard-report-data');
    const docsPanel = document.querySelector('.panel-shell[data-panel="docs"]');
    const reportsPanel = document.querySelector('.panel-shell[data-panel="reports"]');
    const docUnitList = document.querySelector('[data-doc-unit-list="true"]');
    const reportList = document.querySelector('[data-report-unit-list="true"]');
    let reportUnits = [];
    try {
        reportUnits = JSON.parse(reportDataNode?.textContent || '[]') || [];
    } catch (_) {
        reportUnits = [];
    }

    const escapeHtml = (value) => String(value || '')
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;');
    const pickerStates = {
        docs: { hiddenIds: new Set(), labels: new Map(), orderIds: [] },
        reports: { hiddenIds: new Set(), labels: new Map(), orderIds: [] },
    };
    const orderedPickerUnits = (units, state) => {
        const byId = new Map(units.map((unit) => [unit.id, unit]));
        const ordered = [];
        state.orderIds.forEach((id) => {
            const unit = byId.get(id);
            if (unit && !state.hiddenIds.has(id)) ordered.push(unit);
        });
        units.forEach((unit) => {
            if (!state.orderIds.includes(unit.id) && !state.hiddenIds.has(unit.id)) {
                ordered.push(unit);
            }
        });
        state.orderIds = ordered.map((unit) => unit.id);
        return ordered;
    };
    const renderUnitButtons = (list, units, targetAttr, stateName) => {
        if (!list) return;
        document.querySelectorAll(`body > [data-picker-state="${stateName}"][data-picker-menu]`).forEach((menu) => menu.remove());
        const state = pickerStates[stateName] || pickerStates.docs;
        const orderedUnits = orderedPickerUnits(units, state);
        list.innerHTML = orderedUnits.map((unit, index) => {
            const label = state.labels.get(unit.id) || unit.name;
            return `<div class="report-unit-row" data-picker-row="${escapeHtml(unit.id)}">
                <button type="button" class="report-unit-item" data-${targetAttr}="${escapeHtml(unit.id)}">${index + 1}. ${escapeHtml(label)}</button>
                <button type="button" class="report-unit-more" data-picker-more="${escapeHtml(unit.id)}" title="Tùy chọn" aria-label="Tùy chọn">⋮</button>
                <div class="report-unit-action-menu" data-picker-state="${escapeHtml(stateName)}" data-picker-menu="${escapeHtml(unit.id)}" hidden>
                    <button type="button" class="report-unit-action" data-picker-action="rename" data-picker-id="${escapeHtml(unit.id)}" title="Đổi tên" aria-label="Đổi tên">✎</button>
                    <button type="button" class="report-unit-action" data-picker-action="move-up" data-picker-id="${escapeHtml(unit.id)}" title="Di chuyển lên" aria-label="Di chuyển lên">↑</button>
                    <button type="button" class="report-unit-action report-unit-action-delete" data-picker-action="delete" data-picker-id="${escapeHtml(unit.id)}" title="Xóa khỏi danh sách" aria-label="Xóa khỏi danh sách">🗑</button>
                </div>
            </div>`;
        }).join('') || '<p class="muted">Chưa có đơn vị.</p>';
    };
    const filterUnits = (query) => {
        const normalized = String(query || '').trim().toLowerCase();
        if (!normalized) return reportUnits;
        return reportUnits.filter((unit) => String(unit.name || '').toLowerCase().includes(normalized));
    };
    const bindUnitSearch = (name, list, targetAttr, onChoose) => {
        const input = document.querySelector(`[data-unit-search="${name}"]`);
        const render = () => {
            const state = pickerStates[name] || pickerStates.docs;
            const currentUnits = filterUnits(input?.value || '');
            renderUnitButtons(list, currentUnits, targetAttr, name);
            list?.querySelectorAll(`[data-${targetAttr}]`).forEach((button) => {
                button.addEventListener('click', (event) => {
                    event.preventDefault();
                    event.stopPropagation();
                    list.querySelectorAll('.report-unit-item').forEach((item) => item.classList.remove('is-active'));
                    button.classList.add('is-active');
                    onChoose(button.getAttribute(`data-${targetAttr}`) || '');
                });
            });
            list?.querySelectorAll('[data-picker-more]').forEach((button) => {
                button.addEventListener('click', (event) => {
                    event.preventDefault();
                    event.stopPropagation();
                    const rowId = button.getAttribute('data-picker-more') || '';
                    const targetMenu = document.querySelector(`[data-picker-state="${CSS.escape(name)}"][data-picker-menu="${CSS.escape(rowId)}"]`);
                    document.querySelectorAll(`[data-picker-state="${CSS.escape(name)}"][data-picker-menu]`).forEach((menu) => {
                        menu.hidden = menu.getAttribute('data-picker-menu') !== rowId || !menu.hidden;
                    });
                    if (targetMenu && !targetMenu.hidden) {
                        if (targetMenu.parentElement !== document.body) {
                            document.body.appendChild(targetMenu);
                        }
                        const rect = button.getBoundingClientRect();
                        const menuWidth = targetMenu.offsetWidth || 40;
                        const left = Math.max(8, Math.min(window.innerWidth - menuWidth - 8, rect.right - menuWidth));
                        const top = Math.max(8, Math.min(window.innerHeight - targetMenu.offsetHeight - 8, rect.bottom + 4));
                        targetMenu.style.left = `${left}px`;
                        targetMenu.style.top = `${top}px`;
                    }
                });
            });
            list?.querySelectorAll('[data-picker-action]').forEach((button) => {
                button.addEventListener('click', (event) => {
                    event.preventDefault();
                    event.stopPropagation();
                    const action = button.getAttribute('data-picker-action') || '';
                    const unitId = button.getAttribute('data-picker-id') || '';
                    const unit = reportUnits.find((item) => item.id === unitId);
                    if (!unit) return;
                    if (action === 'rename') {
                        const nextName = window.prompt('Nhập tên hiển thị:', state.labels.get(unitId) || unit.name);
                        if (nextName && nextName.trim()) {
                            state.labels.set(unitId, nextName.trim());
                        }
                    } else if (action === 'move-up') {
                        const visibleIds = orderedPickerUnits(currentUnits, state).map((item) => item.id);
                        const index = visibleIds.indexOf(unitId);
                        if (index > 0) {
                            const beforeId = visibleIds[index - 1];
                            const orderIds = state.orderIds.slice();
                            const currentIndex = orderIds.indexOf(unitId);
                            const beforeIndex = orderIds.indexOf(beforeId);
                            if (currentIndex >= 0 && beforeIndex >= 0) {
                                orderIds.splice(currentIndex, 1);
                                orderIds.splice(beforeIndex, 0, unitId);
                                state.orderIds = orderIds;
                            }
                        }
                    } else if (action === 'delete') {
                        state.hiddenIds.add(unitId);
                    }
                    render();
                });
            });
        };
        input?.addEventListener('input', render);
        render();
    };
    bindUnitSearch('docs', docUnitList, 'doc-unit', (unitId) => {
        docsPanel?.classList.remove('is-open');
        window.location.href = `/units/${encodeURIComponent(unitId)}?panel=branch-docs&return_to=%2F`;
    });
    const docSearchInput = document.querySelector('[data-unit-search="docs"]');
    const docSearchToggle = document.querySelector('[data-dashboard-doc-search-toggle="true"]');
    docSearchToggle?.addEventListener('click', (event) => {
        event.preventDefault();
        event.stopPropagation();
        if (!docSearchInput) return;
        const shouldOpen = docSearchInput.hidden;
        docSearchInput.hidden = !shouldOpen;
        docSearchToggle.classList.toggle('is-active', shouldOpen);
        if (shouldOpen) {
            docSearchInput.focus();
            docSearchInput.select();
        } else {
            docSearchInput.value = '';
            docSearchInput.dispatchEvent(new Event('input', { bubbles: true }));
        }
    });
    document.querySelector('[data-dashboard-doc-upload="true"]')?.addEventListener('change', async (event) => {
        const input = event.currentTarget;
        const file = input?.files?.[0];
        if (!file || !dashboardCsrf) return;
        const suggestedUnit = file.name.replace(/\.[^.]+$/, '').trim();
        const unitName = window.prompt('Nhập tên đơn vị cần tải lên:', suggestedUnit);
        if (!unitName || !unitName.trim()) {
            input.value = '';
            return;
        }
        const normalized = unitName.trim().toLowerCase();
        const target = reportUnits.find((unit) => String(unit.name || '').toLowerCase() === normalized);
        if (!target) {
            window.alert('Không tìm thấy đơn vị phù hợp trong danh sách.');
            input.value = '';
            return;
        }
        const formData = new FormData();
        formData.set('csrf', dashboardCsrf);
        formData.set('org_id', target.id);
        formData.set('year', String(new Date().getFullYear()));
        formData.set('return_to', '/');
        formData.set('title', file.name.replace(/\.[^.]+$/, '') || file.name);
        formData.set('document', file, file.name);
        try {
            const response = await fetch('/documents', {
                method: 'POST',
                body: formData,
                credentials: 'same-origin',
                headers: { Accept: 'text/html,application/xhtml+xml' },
            });
            if (!response.ok) {
                window.alert('Không tải lên được tài liệu. Chỉ các đơn vị cấp thấp nhất được tải danh sách.');
                return;
            }
            window.location.href = `/units/${encodeURIComponent(target.id)}?panel=branch-docs&return_to=%2F`;
        } catch (_) {
            window.alert('Không tải lên được tài liệu do lỗi kết nối.');
        } finally {
            input.value = '';
        }
    });
    bindUnitSearch('reports', reportList, 'report-unit', (unitId) => {
        reportsPanel?.classList.remove('is-open');
        window.location.href = `/units/${encodeURIComponent(unitId)}?panel=unit-report&return_to=%2F`;
    });
    document.querySelectorAll('[data-tab-root]').forEach((root) => {
        const buttons = Array.from(root.querySelectorAll('[data-tab-target]'));
        const panels = Array.from(root.querySelectorAll('[data-tab-panel]'));
        buttons.forEach((button) => {
            button.addEventListener('click', () => {
                const target = button.getAttribute('data-tab-target');
                buttons.forEach((item) => item.classList.toggle('is-active', item === button));
                panels.forEach((panel) => panel.classList.toggle('is-active', panel.getAttribute('data-tab-panel') === target));
            });
        });
    });

  const viewport = document.querySelector('[data-tree-viewport]');
  const panzoom = document.getElementById('tree-panzoom');
    if (!viewport || !panzoom) return;
    const svg = viewport.querySelector('svg');

                const viewBox = svg && svg.viewBox && svg.viewBox.baseVal ? svg.viewBox.baseVal : null;
                const VIEWBOX_WIDTH = viewBox && viewBox.width ? viewBox.width : 1600;
                const VIEWBOX_HEIGHT = viewBox && viewBox.height ? viewBox.height : VIEWBOX_WIDTH;
                const VIEWBOX_CENTER_X = VIEWBOX_WIDTH / 2;
                const VIEWBOX_CENTER_Y = VIEWBOX_HEIGHT / 2;
                const initialScale = Number.parseFloat(viewport.getAttribute('data-tree-initial-scale') || '1.12');
                let scale = Number.isFinite(initialScale) ? initialScale : 1.12;
            let tx = VIEWBOX_CENTER_X * (1 - scale);
                let ty = VIEWBOX_CENTER_Y * (1 - scale);
    let dragging = false;
        let moved = false;
    let lastX = 0;
    let lastY = 0;
        let nodeDragging = null;
        let editMode = false;
        let selectedNodeGroup = null;
        let syntheticNodeCount = 0;
        let suppressClearUntil = 0;

        const treeEditToggle = document.querySelector('[data-tree-edit-toggle="true"]');
        const treeSidebar = document.querySelector('[data-tree-edit-sidebar="true"]');
        const treeUndoButton = document.querySelector('[data-tree-undo="true"]');
        const treeForwardButton = document.querySelector('[data-tree-forward="true"]');
        const treeSaveButton = document.querySelector('[data-tree-save="true"]');
        const treeEditCloseButton = document.querySelector('[data-tree-edit-close="true"]');
        const treeUserMapScript = document.getElementById('tree-user-map');
        const treeStateScript = document.getElementById('tree-state-snapshot');
        const initialTreeNodeIds = new Set(Array.from(panzoom.querySelectorAll('g.tree-node-group[data-org-id]')).map((node) => node.getAttribute('data-org-id')).filter(Boolean));
        const treeUserCard = document.querySelector('[data-tree-user-card="true"]');
        const treeRenameCard = document.querySelector('[data-tree-rename-card="true"]');
        const treeUserUsernameInput = treeUserCard?.querySelector('[data-tree-user-username="true"]');
        const treeUserPasswordInput = treeUserCard?.querySelector('[data-tree-user-password="true"]');
        const treeRenameInput = treeRenameCard?.querySelector('[data-tree-rename-input="true"]');
        const treeRenameSave = treeRenameCard?.querySelector('[data-tree-rename-save="true"]');
        const TREE_STATE_STORAGE_KEY = 'website-buu-tree-editor-v2';
        const TREE_LAYOUT_VERSION = 6;
        const treeCredentialSaveTimers = new Map();
        const initialUserAccounts = (() => {
                if (!treeUserMapScript) return {};
                try {
                        return JSON.parse(treeUserMapScript.textContent || '{}') || {};
                } catch (_) {
                        return {};
                }
        })();
        let userAccounts = { ...initialUserAccounts };
        let treeHistory = [];
        let treeFuture = [];

        const nodeEditor = document.createElement('div');
        nodeEditor.className = 'tree-node-editor';
        nodeEditor.hidden = true;
        nodeEditor.innerHTML = [
                '<button type="button" class="tree-node-editor-btn" data-node-action="add" title="Thêm nút con">+</button>',
            '<button type="button" class="tree-node-editor-btn user" data-node-action="user" title="Tạo user" aria-label="Tạo user"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 12.4c2.72 0 4.92-2.2 4.92-4.92S14.72 2.56 12 2.56 7.08 4.76 7.08 7.48 9.28 12.4 12 12.4zm0 2.46c-3.61 0-6.54 2.93-6.54 6.54h13.08c0-3.61-2.93-6.54-6.54-6.54z"/></svg></button>',
                '<button type="button" class="tree-node-editor-btn" data-node-action="rename" title="Đổi tên">✎</button>',
                '<button type="button" class="tree-node-editor-btn delete" data-node-action="delete" title="Xóa nút">🗑</button>',
        ].join('');
        viewport.appendChild(nodeEditor);

    const updateHistoryButtons = () => {
        if (treeUndoButton) treeUndoButton.disabled = treeHistory.length === 0;
        if (treeForwardButton) treeForwardButton.disabled = treeFuture.length === 0;
    };

    const parseTranslate = (value) => {
        const match = /translate\(([-\d.]+)[\s,]+([-\d.]+)\)/.exec(value || '');
        if (!match) return null;
        return { x: Number.parseFloat(match[1]), y: Number.parseFloat(match[2]) };
    };
    const setTranslate = (node, x, y) => {
        node.setAttribute('transform', `translate(${x.toFixed(3)} ${y.toFixed(3)})`);
    };
    const nodeTier = (node) => {
        const classes = node.getAttribute('class') || '';
        const match = /tier-(\d+)/.exec(classes);
        return match ? Number.parseInt(match[1], 10) : 3;
    };
    const nodeRadiusByTier = (tier) => {
        if (tier === 0) return 84;
        if (tier === 1) return 54;
        if (tier === 2) return 39;
        if (tier === 3) return 30;
        return 22;
    };
    const nodeBoxByTier = (tier) => {
        if (tier === 0) return { width: 220, height: 86, radius: 16 };
        if (tier === 1) return { width: 158, height: 64, radius: 14 };
        if (tier === 2) return { width: 132, height: 54, radius: 12 };
        if (tier === 3) return { width: 108, height: 46, radius: 10 };
        return { width: 78, height: 34, radius: 8 };
    };
    const getNodeGroup = (target) => {
        if (!target || !target.closest) return null;
        const direct = target.closest('g.tree-node-group');
        if (direct) return direct;
        const link = target.closest('a.tree-node-link');
        return link ? link.querySelector('g.tree-node-group') : null;
    };
    const isNodeTarget = (target) => !!getNodeGroup(target);
    const getNodeId = (nodeGroup) => {
        if (!nodeGroup) return null;
        return nodeGroup.getAttribute('data-org-id') || nodeGroup.getAttribute('data-node-id');
    };
    const findNodeGroupById = (nodeId) => {
        if (!nodeId) return null;
        const all = Array.from(panzoom.querySelectorAll('g.tree-node-group'));
        return all.find((item) => getNodeId(item) === nodeId) || null;
    };
    const nodeWorldToViewport = (x, y) => {
        const rect = viewport.getBoundingClientRect();
        return {
            left: ((x * scale + tx) / VIEWBOX_WIDTH) * rect.width,
            top: ((y * scale + ty) / VIEWBOX_HEIGHT) * rect.height,
            rect,
        };
    };
    const positionEditorForNode = (nodeGroup) => {
        if (!nodeGroup || nodeEditor.hidden) return;
        const pos = parseTranslate(nodeGroup.getAttribute('transform'));
        if (!pos) return;
        const projected = nodeWorldToViewport(pos.x, pos.y);
        const clampedLeft = Math.max(30, Math.min(projected.rect.width - 30, projected.left));
        const top = Math.min(projected.rect.height - 90, projected.top + 16);
        nodeEditor.style.left = `${clampedLeft}px`;
        nodeEditor.style.top = `${Math.max(8, top)}px`;
    };
    const positionUserCardForNode = (nodeGroup) => {
        if (!nodeGroup || !treeUserCard || treeUserCard.hidden) return;
        const pos = parseTranslate(nodeGroup.getAttribute('transform'));
        if (!pos) return;
        const projected = nodeWorldToViewport(pos.x, pos.y);
        const clampedLeft = Math.max(96, Math.min(projected.rect.width - 96, projected.left));
        const top = Math.min(projected.rect.height - 120, projected.top + 64);
        treeUserCard.style.left = `${clampedLeft}px`;
        treeUserCard.style.top = `${Math.max(12, top)}px`;
    };
    const positionRenameCardForNode = (nodeGroup) => {
        if (!nodeGroup || !treeRenameCard || treeRenameCard.hidden) return;
        const pos = parseTranslate(nodeGroup.getAttribute('transform'));
        if (!pos) return;
        const projected = nodeWorldToViewport(pos.x, pos.y);
        const clampedLeft = Math.max(132, Math.min(projected.rect.width - 132, projected.left));
        const top = Math.min(projected.rect.height - 120, projected.top + 64);
        treeRenameCard.style.left = `${clampedLeft}px`;
        treeRenameCard.style.top = `${Math.max(12, top)}px`;
    };
    const hideUserCard = () => {
        if (!treeUserCard) return;
        treeUserCard.hidden = true;
    };
    const hideRenameCard = () => {
        if (!treeRenameCard || !treeRenameInput) return;
        treeRenameCard.hidden = true;
        treeRenameInput.dataset.nodeId = '';
    };
    const clearNodeSelection = () => {
        selectedNodeGroup = null;
        nodeEditor.hidden = true;
        hideUserCard();
        hideRenameCard();
    };
    const currentSnapshot = () => ({
        layoutVersion: TREE_LAYOUT_VERSION,
        panzoomHtml: panzoom.innerHTML,
        userAccounts,
        syntheticNodeCount,
        scale,
        tx,
        ty,
    });
    const pushHistory = () => {
        persistUserDraft();
        treeHistory.push(JSON.stringify(currentSnapshot()));
        if (treeHistory.length > 40) treeHistory.shift();
        treeFuture = [];
        updateHistoryButtons();
    };
    const applySnapshot = (snapshot) => {
        if (!snapshot) return;
        const layoutVersionMismatch = snapshot.layoutVersion !== TREE_LAYOUT_VERSION;
        if (snapshot.panzoomHtml) {
            const template = document.createElement('template');
            template.innerHTML = snapshot.panzoomHtml;
            const snapshotIds = Array.from(template.content.querySelectorAll('g.tree-node-group[data-org-id]'))
                .map((node) => node.getAttribute('data-org-id'))
                .filter(Boolean);
            const hasOutOfScopeNode = snapshotIds.some((id) => !initialTreeNodeIds.has(id) && !String(id).startsWith('synthetic-'));
            const hasLegacyCircleNodes = template.content.querySelector('circle.tree-node');
            const hasLegacyIconNodes = template.content.querySelector('.tree-node-icon');
            if (layoutVersionMismatch || hasOutOfScopeNode || hasLegacyCircleNodes || hasLegacyIconNodes) {
                snapshot = { ...snapshot, panzoomHtml: '' };
            }
        }
        clearNodeSelection();
        panzoom.innerHTML = snapshot.panzoomHtml || panzoom.innerHTML;
        userAccounts = snapshot.userAccounts || { ...initialUserAccounts };
        syntheticNodeCount = snapshot.syntheticNodeCount || 0;
        if (!layoutVersionMismatch) {
            scale = Number.isFinite(snapshot.scale) ? snapshot.scale : scale;
            tx = Number.isFinite(snapshot.tx) ? snapshot.tx : tx;
            ty = Number.isFinite(snapshot.ty) ? snapshot.ty : ty;
        }
        apply();
        if (layoutVersionMismatch) {
            resetTreeView();
        }
        updateHistoryButtons();
    };
    const saveTreeState = async () => {
        const snapshotText = JSON.stringify(currentSnapshot());
        try {
            window.localStorage.setItem(TREE_STATE_STORAGE_KEY, snapshotText);
            if (treeSaveButton) treeSaveButton.title = 'Đã lưu';
        } catch (_) {}
        if (!dashboardCsrf) return;
        const payload = new URLSearchParams();
        payload.set('csrf', dashboardCsrf);
        payload.set('snapshot', snapshotText);
        try {
            const response = await fetch('/dashboard/tree-state', {
                method: 'POST',
                credentials: 'same-origin',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
                    Accept: 'application/json',
                },
                body: payload.toString(),
            });
            if (treeSaveButton) treeSaveButton.title = response.ok ? 'Đã lưu lên server' : 'Chưa lưu được lên server';
        } catch (_) {
            if (treeSaveButton) treeSaveButton.title = 'Chưa lưu được lên server';
        }
    };
    const loadTreeState = () => {
        try {
            const serverRaw = JSON.parse(treeStateScript?.textContent || '""');
            if (serverRaw) {
                applySnapshot(JSON.parse(serverRaw));
                return;
            }
            const raw = window.localStorage.getItem(TREE_STATE_STORAGE_KEY);
            if (!raw) return;
            applySnapshot(JSON.parse(raw));
        } catch (_) {}
        updateHistoryButtons();
    };
    const unitDisplayLabel = (value) => {
        const trimmed = (value || '').trim();
        if (!trimmed || /^đơn vị\s+/i.test(trimmed)) return trimmed;
        return `Đơn vị ${trimmed}`;
    };
    const nodeLabel = (nodeGroup) => (nodeGroup?.querySelector('text.tree-node-text')?.textContent || '').trim();
    const canPersistTreeUser = (nodeId) => !!(nodeId && initialUserAccounts[nodeId] && dashboardCsrf);
    const saveTreeUserCredentials = async (nodeId) => {
        if (!canPersistTreeUser(nodeId)) return;
        const record = userAccounts[nodeId];
        if (!record) return;
        const username = (record.username || '').trim();
        const password = (record.password || '').trim();
        if (!username || !password) return;
        const payload = new URLSearchParams();
        payload.set('csrf', dashboardCsrf);
        payload.set('username', username);
        payload.set('password', password);
        try {
            const result = await syncClient?.submitServerAction({
                type: 'tree-user-credentials',
                request: {
                    url: `/dashboard/tree-users/${encodeURIComponent(nodeId)}`,
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
                        Accept: 'application/json',
                    },
                    body: payload.toString(),
                },
                responseType: 'json',
                queueMessage: 'Đã lưu tài khoản cây vào hàng đợi đồng bộ.',
            });
            if (!result?.ok || result.queued || !result.payload) return;
            const saved = result.payload;
            userAccounts[nodeId] = {
                username: saved?.username || username,
                password: saved?.password || password,
            };
            initialUserAccounts[nodeId] = { ...userAccounts[nodeId] };
            if ((treeUserUsernameInput?.dataset.nodeId || '') === nodeId) {
                treeUserUsernameInput.value = userAccounts[nodeId].username;
                treeUserPasswordInput.value = userAccounts[nodeId].password;
            }
        } catch (_) {}
    };
    const scheduleTreeUserSave = (nodeId) => {
        if (!canPersistTreeUser(nodeId)) return;
        const existingTimer = treeCredentialSaveTimers.get(nodeId);
        if (existingTimer) {
            window.clearTimeout(existingTimer);
        }
        const nextTimer = window.setTimeout(() => {
            treeCredentialSaveTimers.delete(nodeId);
            saveTreeUserCredentials(nodeId);
        }, 360);
        treeCredentialSaveTimers.set(nodeId, nextTimer);
    };
    const openUserCard = (nodeGroup) => {
        if (!treeUserCard || !treeUserUsernameInput || !treeUserPasswordInput || !nodeGroup) return;
        const nodeId = getNodeId(nodeGroup);
        const label = nodeLabel(nodeGroup) || 'node';
        const existing = nodeId ? userAccounts[nodeId] : null;
        treeUserUsernameInput.value = existing?.username || label;
        treeUserPasswordInput.value = existing?.password || label;
        treeUserUsernameInput.dataset.nodeId = nodeId || '';
        treeUserPasswordInput.dataset.nodeId = nodeId || '';
        treeUserCard.hidden = false;
        hideRenameCard();
        positionUserCardForNode(nodeGroup);
    };
    const submitRename = () => {
        if (!treeRenameInput) return;
        const nodeId = treeRenameInput.dataset.nodeId || '';
        if (!nodeId) return;
        const nodeGroup = findNodeGroupById(nodeId);
        const text = nodeGroup?.querySelector('text.tree-node-text');
        if (!nodeGroup || !text) return;
        const nextName = treeRenameInput.value.trim();
        if (!nextName) {
            treeRenameInput.focus();
            return;
        }
        if (nextName === (text.textContent || '').trim()) {
            hideRenameCard();
            return;
        }
        pushHistory();
        text.textContent = unitDisplayLabel(nextName);
        hideRenameCard();
        selectNode(nodeGroup);
    };
    const openRenameCard = (nodeGroup) => {
        if (!treeRenameCard || !treeRenameInput || !nodeGroup) return;
        const nodeId = getNodeId(nodeGroup);
        if (!nodeId) return;
        treeRenameInput.value = nodeLabel(nodeGroup);
        treeRenameInput.dataset.nodeId = nodeId;
        treeRenameCard.hidden = false;
        hideUserCard();
        positionRenameCardForNode(nodeGroup);
        requestAnimationFrame(() => {
            treeRenameInput.focus();
            treeRenameInput.select();
        });
    };
    const persistUserDraft = () => {
        const nodeId = treeUserUsernameInput?.dataset.nodeId || treeUserPasswordInput?.dataset.nodeId || '';
        if (!nodeId || !treeUserUsernameInput || !treeUserPasswordInput) return;
        userAccounts[nodeId] = {
            username: treeUserUsernameInput.value.trim() || nodeLabel(selectedNodeGroup) || 'user',
            password: treeUserPasswordInput.value.trim() || nodeLabel(selectedNodeGroup) || 'user',
        };
        scheduleTreeUserSave(nodeId);
    };
    const selectNode = (nodeGroup) => {
        if (!editMode || !nodeGroup) return;
        selectedNodeGroup = nodeGroup;
        nodeEditor.hidden = false;
        suppressClearUntil = performance.now() + 180;
        positionEditorForNode(nodeGroup);
        positionUserCardForNode(nodeGroup);
        positionRenameCardForNode(nodeGroup);
    };
    const updateEdgesForNode = (nodeId) => {
        if (!nodeId) return;
        const source = findNodeGroupById(nodeId);
        if (!source) return;
        const sourcePos = parseTranslate(source.getAttribute('transform'));
        if (!sourcePos) return;
        const sourceRadius = nodeRadiusByTier(nodeTier(source));
        panzoom.querySelectorAll('line.tree-edge').forEach((edge) => {
            const fromId = edge.getAttribute('data-from-id');
            const toId = edge.getAttribute('data-to-id');
            if (fromId !== nodeId && toId !== nodeId) return;
            const otherId = fromId === nodeId ? toId : fromId;
            const other = findNodeGroupById(otherId);
            if (!other) return;
            const otherPos = parseTranslate(other.getAttribute('transform'));
            if (!otherPos) return;
            const otherRadius = nodeRadiusByTier(nodeTier(other));
            const dx = otherPos.x - sourcePos.x;
            const dy = otherPos.y - sourcePos.y;
            const distance = Math.hypot(dx, dy) || 1;
            const ux = dx / distance;
            const uy = dy / distance;

            if (fromId === nodeId) {
                edge.setAttribute('x1', (sourcePos.x + ux * sourceRadius).toFixed(2));
                edge.setAttribute('y1', (sourcePos.y + uy * sourceRadius).toFixed(2));
                edge.setAttribute('x2', (otherPos.x - ux * otherRadius).toFixed(2));
                edge.setAttribute('y2', (otherPos.y - uy * otherRadius).toFixed(2));
            } else {
                edge.setAttribute('x2', (sourcePos.x + ux * sourceRadius).toFixed(2));
                edge.setAttribute('y2', (sourcePos.y + uy * sourceRadius).toFixed(2));
                edge.setAttribute('x1', (otherPos.x - ux * otherRadius).toFixed(2));
                edge.setAttribute('y1', (otherPos.y - uy * otherRadius).toFixed(2));
            }
        });
    };
    const setEditMode = (enabled) => {
        editMode = !!enabled;
        viewport.classList.toggle('edit-mode', editMode);
        if (treeSidebar) treeSidebar.hidden = !editMode;
        if (treeEditToggle) {
            treeEditToggle.setAttribute('data-editing', editMode ? 'true' : 'false');
            treeEditToggle.title = editMode ? 'Tắt chỉnh sửa cây' : 'Chỉnh sửa cây';
            if (editMode) {
                treeEditToggle.style.background = '#111111';
                treeEditToggle.style.borderColor = '#111111';
                treeEditToggle.style.color = '#ffffff';
                treeEditToggle.style.boxShadow = 'none';
            } else {
                treeEditToggle.style.background = '#ffffff';
                treeEditToggle.style.borderColor = '#111111';
                treeEditToggle.style.color = '#111111';
                treeEditToggle.style.boxShadow = 'none';
            }
        }
        if (!editMode) {
            clearNodeSelection();
        }
    };

    panzoom.addEventListener('click', (event) => {
        if (!editMode) return;
        const link = event.target.closest && event.target.closest('a.tree-node-link');
        if (!link) return;
        event.preventDefault();
        event.stopPropagation();
    }, true);

  const apply = () => {
    panzoom.setAttribute('transform', `translate(${tx} ${ty}) scale(${scale})`);
    if (selectedNodeGroup && !nodeEditor.hidden) {
        positionEditorForNode(selectedNodeGroup);
    }
        if (selectedNodeGroup && treeUserCard && !treeUserCard.hidden) {
                positionUserCardForNode(selectedNodeGroup);
        }
  };

    const resetTreeView = () => {
        let bbox = null;
        try {
            bbox = panzoom.getBBox();
        } catch (_) {
            bbox = null;
        }
        if (bbox && bbox.width > 0 && bbox.height > 0) {
            const fitScale = Math.min(
                VIEWBOX_WIDTH * 0.92 / bbox.width,
                VIEWBOX_HEIGHT * 0.88 / bbox.height,
                1.28,
            );
            scale = Number.isFinite(fitScale) ? Math.max(0.54, fitScale) : (Number.isFinite(initialScale) ? initialScale : 1);
            tx = VIEWBOX_CENTER_X - (bbox.x + bbox.width / 2) * scale;
            ty = VIEWBOX_CENTER_Y - (bbox.y + bbox.height / 2) * scale;
        } else {
            scale = Number.isFinite(initialScale) ? initialScale : 1;
            tx = VIEWBOX_CENTER_X * (1 - scale);
            ty = VIEWBOX_CENTER_Y * (1 - scale);
        }
        apply();
    };
    const treeHasVisibleNode = () => {
        const viewportRect = viewport.getBoundingClientRect();
        const margin = 24;
        return Array.from(panzoom.querySelectorAll('g.tree-node-group')).some((node) => {
            const rect = node.getBoundingClientRect();
            if (!rect.width || !rect.height) return false;
            return rect.right >= viewportRect.left + margin
                && rect.left <= viewportRect.right - margin
                && rect.bottom >= viewportRect.top + margin
                && rect.top <= viewportRect.bottom - margin;
        });
    };
    const ensureTreeVisible = () => {
        window.requestAnimationFrame(() => {
            if (!treeHasVisibleNode()) {
                resetTreeView();
            }
        });
    };

        loadTreeState();
        ensureTreeVisible();
        window.addEventListener('resize', ensureTreeVisible);

    const viewportPoint = (clientX, clientY) => {
        const rect = viewport.getBoundingClientRect();
        return {
            pointX: ((clientX - rect.left) / rect.width) * VIEWBOX_WIDTH,
            pointY: ((clientY - rect.top) / rect.height) * VIEWBOX_HEIGHT,
            rect,
        };
    };

  viewport.addEventListener('wheel', (event) => {
    event.preventDefault();
        const { pointX, pointY } = viewportPoint(event.clientX, event.clientY);
                const next = Math.min(2.8, Math.max(0.54, scale * (event.deltaY < 0 ? 1.18 : 0.86)));
    const worldX = (pointX - tx) / scale;
    const worldY = (pointY - ty) / scale;
    tx = pointX - worldX * next;
    ty = pointY - worldY * next;
    scale = next;
    apply();
  }, { passive: false });

  viewport.addEventListener('pointerdown', (event) => {
        if (event.target.closest('.tree-node-editor')) {
            return;
        }
        if (event.target.closest('.tree-user-card')) {
            return;
        }
        if (event.target.closest('[data-tree-edit-sidebar="true"]')) {
            return;
        }
        const hitNode = getNodeGroup(event.target);
        if (editMode && hitNode) {
            event.preventDefault();
            event.stopPropagation();
            moved = false;
            pushHistory();
            nodeDragging = {
                node: hitNode,
                lastX: event.clientX,
                lastY: event.clientY,
                pointerId: event.pointerId,
            };
            selectNode(hitNode);
            viewport.setPointerCapture(event.pointerId);
            return;
        }
        if (isNodeTarget(event.target)) {
            return;
        }
    dragging = true;
        moved = false;
    viewport.classList.add('dragging');
    lastX = event.clientX;
    lastY = event.clientY;
    viewport.setPointerCapture(event.pointerId);
  });

  viewport.addEventListener('pointermove', (event) => {
    if (nodeDragging) {
        const { rect } = viewportPoint(event.clientX, event.clientY);
        const dx = event.clientX - nodeDragging.lastX;
        const dy = event.clientY - nodeDragging.lastY;
        if (Math.abs(dx) > 1 || Math.abs(dy) > 1) {
            moved = true;
        }
        const current = parseTranslate(nodeDragging.node.getAttribute('transform'));
        if (current) {
            const worldDx = (dx / rect.width) * VIEWBOX_WIDTH / scale;
            const worldDy = (dy / rect.height) * VIEWBOX_HEIGHT / scale;
            setTranslate(nodeDragging.node, current.x + worldDx, current.y + worldDy);
            const nodeId = getNodeId(nodeDragging.node);
            updateEdgesForNode(nodeId);
            positionEditorForNode(nodeDragging.node);
        }
        nodeDragging.lastX = event.clientX;
        nodeDragging.lastY = event.clientY;
        return;
    }
    if (!dragging) return;
        const { rect } = viewportPoint(event.clientX, event.clientY);
        const dx = event.clientX - lastX;
        const dy = event.clientY - lastY;
        if (Math.abs(dx) > 2 || Math.abs(dy) > 2) {
            moved = true;
        }
        tx += (dx / rect.width) * VIEWBOX_WIDTH;
        ty += (dy / rect.height) * VIEWBOX_HEIGHT;
    lastX = event.clientX;
    lastY = event.clientY;
    apply();
  });

  const stopDragging = (event) => {
    if (nodeDragging) {
        nodeDragging = null;
        if (event.pointerId !== undefined) {
          try { viewport.releasePointerCapture(event.pointerId); } catch (_) {}
        }
        return;
    }
    if (!dragging) return;
    dragging = false;
    viewport.classList.remove('dragging');
    if (event.pointerId !== undefined) {
      try { viewport.releasePointerCapture(event.pointerId); } catch (_) {}
    }
  };

  viewport.addEventListener('pointerup', stopDragging);
  viewport.addEventListener('pointercancel', stopDragging);

    if (svg) {
        svg.addEventListener('click', (event) => {
            const nodeGroup = getNodeGroup(event.target);
            if (editMode) {
                if (nodeGroup) {
                    event.preventDefault();
                    event.stopPropagation();
                    selectNode(nodeGroup);
                }
                return;
            }
            const link = event.target.closest && event.target.closest('a.tree-node-link');
            if (!link || moved) {
                return;
            }
            const href = link.getAttribute('href');
            if (href) {
                window.location.href = href;
            }
        });
    }

    const addNodeButton = nodeEditor.querySelector('[data-node-action="add"]');
    const userNodeButton = nodeEditor.querySelector('[data-node-action="user"]');
    const renameNodeButton = nodeEditor.querySelector('[data-node-action="rename"]');
    const deleteNodeButton = nodeEditor.querySelector('[data-node-action="delete"]');

    addNodeButton?.addEventListener('click', (event) => {
        event.preventDefault();
        event.stopPropagation();
        if (!selectedNodeGroup) return;
        pushHistory();
        const parentPos = parseTranslate(selectedNodeGroup.getAttribute('transform'));
        if (!parentPos) return;
        const parentId = getNodeId(selectedNodeGroup);
        if (!parentId) return;
        const parentTier = nodeTier(selectedNodeGroup);
        const childTier = Math.min(parentTier + 1, 3);
        const parentRadius = nodeRadiusByTier(parentTier);
        const childRadius = nodeRadiusByTier(childTier);
        syntheticNodeCount += 1;
        const childId = `custom-${Date.now()}-${syntheticNodeCount}`;
        const childX = parentPos.x + (parentRadius + childRadius + 24);
        const childY = parentPos.y + (syntheticNodeCount % 2 === 0 ? 36 : -36);

        const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
        line.setAttribute('class', 'tree-edge tree-edit-edge');
        line.setAttribute('data-from-id', parentId);
        line.setAttribute('data-to-id', childId);
        line.setAttribute('x1', parentPos.x.toFixed(2));
        line.setAttribute('y1', parentPos.y.toFixed(2));
        line.setAttribute('x2', childX.toFixed(2));
        line.setAttribute('y2', childY.toFixed(2));
        panzoom.insertBefore(line, panzoom.firstChild);

        const node = document.createElementNS('http://www.w3.org/2000/svg', 'g');
        node.setAttribute('class', `tree-node-group tier-${childTier} tree-edit-node`);
        node.setAttribute('data-node-id', childId);
        setTranslate(node, childX, childY);

        const box = nodeBoxByTier(childTier);
        const rect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
        rect.setAttribute('class', 'tree-node');
        rect.setAttribute('x', String(-box.width / 2));
        rect.setAttribute('y', String(-box.height / 2));
        rect.setAttribute('width', String(box.width));
        rect.setAttribute('height', String(box.height));
        rect.setAttribute('rx', String(box.radius));
        rect.setAttribute('ry', String(box.radius));

        const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        text.setAttribute('class', 'tree-node-text');
        text.setAttribute('text-anchor', 'middle');
        text.setAttribute('dominant-baseline', 'middle');
        text.textContent = unitDisplayLabel(`mới${syntheticNodeCount}`);

        node.appendChild(rect);
        node.appendChild(text);
        panzoom.appendChild(node);

        updateEdgesForNode(parentId);
        updateEdgesForNode(childId);
        selectNode(node);
    });

    userNodeButton?.addEventListener('click', (event) => {
        event.preventDefault();
        event.stopPropagation();
        if (!selectedNodeGroup) return;
        openUserCard(selectedNodeGroup);
    });

    renameNodeButton?.addEventListener('click', (event) => {
        event.preventDefault();
        event.stopPropagation();
        if (!selectedNodeGroup) return;
        openRenameCard(selectedNodeGroup);
    });

    deleteNodeButton?.addEventListener('click', (event) => {
        event.preventDefault();
        event.stopPropagation();
        if (!selectedNodeGroup) return;
        pushHistory();
        const nodeId = getNodeId(selectedNodeGroup);
        if (!nodeId) return;
        const edges = Array.from(panzoom.querySelectorAll('line.tree-edge'));
        edges.forEach((edge) => {
            if (edge.getAttribute('data-from-id') === nodeId || edge.getAttribute('data-to-id') === nodeId) {
                edge.remove();
            }
        });
        const container = selectedNodeGroup.closest('a.tree-node-link') || selectedNodeGroup;
        container.remove();
        clearNodeSelection();
    });

    treeUserUsernameInput?.addEventListener('input', persistUserDraft);
    treeUserPasswordInput?.addEventListener('input', persistUserDraft);
    treeRenameSave?.addEventListener('click', (event) => {
        event.preventDefault();
        event.stopPropagation();
        submitRename();
    });
    treeRenameInput?.addEventListener('keydown', (event) => {
        if (event.key === 'Enter') {
            event.preventDefault();
            submitRename();
        }
        if (event.key === 'Escape') {
            event.preventDefault();
            hideRenameCard();
        }
    });

    treeUndoButton?.addEventListener('click', (event) => {
        event.preventDefault();
        event.stopPropagation();
        persistUserDraft();
        const previous = treeHistory.pop();
        if (!previous) return;
        try {
            treeFuture.push(JSON.stringify(currentSnapshot()));
            applySnapshot(JSON.parse(previous));
        } catch (_) {}
    });

    treeForwardButton?.addEventListener('click', (event) => {
        event.preventDefault();
        event.stopPropagation();
        persistUserDraft();
        const next = treeFuture.pop();
        if (!next) return;
        try {
            treeHistory.push(JSON.stringify(currentSnapshot()));
            applySnapshot(JSON.parse(next));
        } catch (_) {}
    });

    treeSaveButton?.addEventListener('click', (event) => {
        event.preventDefault();
        event.stopPropagation();
        persistUserDraft();
        saveTreeState();
    });

    treeEditCloseButton?.addEventListener('click', (event) => {
        event.preventDefault();
        event.stopPropagation();
        setEditMode(false);
    });

    window.setInterval(() => {
        if (!editMode) return;
        persistUserDraft();
        saveTreeState();
    }, 10 * 60 * 1000);

    if (treeEditToggle) {
        treeEditToggle.addEventListener('click', (event) => {
            event.preventDefault();
            event.stopPropagation();
            setEditMode(!editMode);
        });
    }

    document.addEventListener('click', (event) => {
        if (!editMode || nodeEditor.hidden) return;
        if (performance.now() < suppressClearUntil) return;
        if (event.target.closest('.tree-node-editor')) return;
        if (event.target.closest('.tree-user-card')) return;
        if (event.target.closest('.tree-rename-card')) return;
        if (event.target.closest('[data-tree-edit-sidebar="true"]')) return;
        if (getNodeGroup(event.target)) return;
        clearNodeSelection();
    });

    closePanels();


    // ── LAN Mode Toggle Button ──
    const lanButton = document.querySelector('[data-lan-toggle="true"]');
    const ipToggleButton = document.querySelector('[data-ip-toggle="true"]');
    const ipSection = document.querySelector('[data-ip-section="true"]');
    const ipList = ipSection?.querySelector('[data-ip-list="true"]');
    const ipAddButton = ipSection?.querySelector('[data-ip-add="true"]');
    const passwordToggleButton = document.querySelector('[data-password-toggle="true"]');
    const passwordPanel = document.querySelector('[data-password-panel="true"]');
    const passwordCurrentInput = document.querySelector('[data-password-current="true"]');
    const passwordNextInput = document.querySelector('[data-password-next="true"]');
    const passwordSaveButton = document.querySelector('[data-password-save="true"]');

    const clearPasswordInputs = () => {
        if (passwordCurrentInput) passwordCurrentInput.value = '';
        if (passwordNextInput) passwordNextInput.value = '';
    };

    const syncIpButton = () => {
        if (!ipToggleButton || !ipSection) return;
        const open = ipSection.classList.contains('is-open');
        ipToggleButton.style.background = open ? '#111111' : '#ffffff';
        ipToggleButton.style.borderColor = '#111111';
        ipToggleButton.style.color = open ? '#ffffff' : '#111111';
    };
    const attachIpRowEvents = (row) => {
        const removeButton = row?.querySelector('.remove-ip-btn');
        removeButton?.addEventListener('click', (event) => {
            event.preventDefault();
            event.stopPropagation();
            row.remove();
        });
    };
    const createIpRow = (value = '') => {
        const row = document.createElement('div');
        row.className = 'ip-row';
        row.innerHTML = '<input type="text" class="ip-row-input" spellcheck="false"><button type="button" class="remove-ip-btn" aria-label="Xóa IP" title="Xóa IP">×</button>';
        const input = row.querySelector('.ip-row-input');
        if (input) input.value = value;
        attachIpRowEvents(row);
        return row;
    };
    const ensureMinimumIpRows = (minimum = 3) => {
        if (!ipList) return;
        const rows = Array.from(ipList.querySelectorAll('.ip-row'));
        const filledRows = rows.filter((row) => {
            const input = row.querySelector('.ip-row-input');
            return !!(input && input.value.trim());
        });
        let totalRows = rows.length;
        const targetRows = Math.max(minimum, filledRows.length);
        while (totalRows < targetRows) {
            ipList.appendChild(createIpRow(''));
            totalRows += 1;
        }
    };
    ipList?.querySelectorAll('.ip-row').forEach((row) => attachIpRowEvents(row));
    ensureMinimumIpRows();
    ipAddButton?.addEventListener('click', (event) => {
        event.preventDefault();
        event.stopPropagation();
        const row = createIpRow('');
        ipList?.appendChild(row);
        row.querySelector('.ip-row-input')?.focus();
    });
    ipToggleButton?.addEventListener('click', (event) => {
        event.preventDefault();
        event.stopPropagation();
        if (!ipSection) return;
        ipSection.classList.toggle('is-open');
        if (ipSection.classList.contains('is-open')) {
            ensureMinimumIpRows();
        }
        syncIpButton();
    });

    passwordToggleButton?.addEventListener('click', (event) => {
        event.preventDefault();
        event.stopPropagation();
        if (!passwordPanel) return;
        const nextHidden = !passwordPanel.hidden;
        passwordPanel.hidden = nextHidden;
        if (!nextHidden) {
            passwordCurrentInput?.focus();
        }
    });

    passwordSaveButton?.addEventListener('click', async (event) => {
        event.preventDefault();
        event.stopPropagation();
        if (!dashboardCsrf || !passwordCurrentInput || !passwordNextInput || !passwordSaveButton) {
            return;
        }
        if (!clientUi.requireOnline()) {
            return;
        }
        const currentPassword = passwordCurrentInput.value || '';
        const newPassword = passwordNextInput.value || '';
        if (!currentPassword.trim() || !newPassword.trim()) {
            clientUi.showNotice('Cần nhập đủ mật khẩu cũ và mật khẩu mới.', 'error');
            return;
        }

        passwordSaveButton.disabled = true;
        clientUi.showNotice('Đang lưu mật khẩu...', 'success');
        try {
            const body = new URLSearchParams();
            body.set('csrf', dashboardCsrf);
            body.set('current_password', currentPassword);
            body.set('new_password', newPassword);
            body.set('confirm_password', newPassword);
            const result = await syncClient?.submitServerAction({
                type: 'password-change',
                request: {
                    url: '/settings/password',
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                        Accept: 'application/json',
                    },
                    body: body.toString(),
                },
                responseType: 'json',
                queueMessage: 'Đã lưu yêu cầu đổi mật khẩu, sẽ gửi khi online.',
            });
            if (!result?.ok) {
                clientUi.showNotice(result?.payload?.message || 'Không đổi được mật khẩu.', 'error');
                return;
            }
            clearPasswordInputs();
            if (passwordPanel) {
                passwordPanel.hidden = true;
            }
            clientUi.showNotice(
                result.queued ? 'Đã lưu yêu cầu đổi mật khẩu, sẽ gửi khi online.' : (result.payload?.message || 'Đã đổi mật khẩu tài khoản.'),
                'success',
            );
        } catch (_) {
            clientUi.showNotice('Không kết nối được tới máy chủ để đổi mật khẩu.', 'error');
        } finally {
            passwordSaveButton.disabled = false;
        }
    });

    const syncLanUi = () => {
        if (!lanButton) return;
        const isLan = lanButton.getAttribute('data-is-lan') === 'true';
        if (isLan) {
            lanButton.style.background = 'rgba(115, 255, 232, 0.42)';
            lanButton.style.borderColor = 'rgba(177, 255, 242, 0.74)';
            lanButton.style.color = '#023838';
            lanButton.style.boxShadow = '0 0 10px rgba(101, 255, 228, 0.34), 0 0 18px rgba(101, 255, 228, 0.2)';
        } else {
            lanButton.style.background = 'rgba(143, 247, 234, 0.1)';
            lanButton.style.borderColor = 'rgba(143, 247, 234, 0.2)';
            lanButton.style.color = 'rgba(143, 247, 234, 0.6)';
            lanButton.style.boxShadow = 'none';
        }
        // The IP editor belongs to LAN mode and stays beside the LAN button.
        if (ipToggleButton) {
            ipToggleButton.hidden = !isLan;
            if (!isLan && ipSection) {
                ipSection.classList.remove('is-open');
            }
        }
    };

    const collectWhitelist = () => Array.from(ipList?.querySelectorAll('.ip-row-input') || [])
        .map((input) => (input.value || '').trim())
        .filter((value, index, all) => value && all.indexOf(value) === index);

    const replaceWhitelistRows = (values = []) => {
        if (!ipList) return;
        ipList.innerHTML = '';
        values.forEach((value) => ipList.appendChild(createIpRow(value)));
        ensureMinimumIpRows();
    };

    const updateNetworkMode = async (mode) => {
        if (!lanButton || !dashboardCsrf) return false;
        const previous = lanButton.getAttribute('data-is-lan') === 'true';
        const whitelist = collectWhitelist();
        lanButton.disabled = true;
        try {
            const body = new URLSearchParams();
            body.set('csrf', dashboardCsrf);
            body.set('mode', mode);
            body.set('ip_whitelist', whitelist.join('\n'));
            const queuedModeIsLan = mode === 'lan-only';
            const response = await syncClient?.submitServerAction({
                type: 'network-settings',
                request: {
                    url: '/settings/network',
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                        Accept: 'application/json',
                    },
                    body: body.toString(),
                },
                responseType: 'json',
                queueMessage: 'Đã lưu thay đổi mạng, sẽ gửi khi online.',
            });
            if (!response?.ok) {
                lanButton.setAttribute('data-is-lan', previous.toString());
                syncLanUi();
                clientUi.showNotice('Không cập nhật được chế độ mạng.', 'error');
                return false;
            }
            const payload = response.payload || {};
            lanButton.setAttribute('data-is-lan', String(response.queued ? queuedModeIsLan : !!payload?.is_lan));
            replaceWhitelistRows(Array.isArray(payload?.ip_whitelist) ? payload.ip_whitelist : whitelist);
            syncLanUi();
            clientUi.showNotice(response.queued ? 'Đã lưu thay đổi mạng, sẽ gửi khi online.' : 'Đã cập nhật chế độ mạng.', 'success');
            return true;
        } catch (_) {
            lanButton.setAttribute('data-is-lan', previous.toString());
            syncLanUi();
            clientUi.showNotice('Không kết nối được tới máy chủ để đổi chế độ mạng.', 'error');
            return false;
        } finally {
            lanButton.disabled = false;
        }
    };
    
    if (lanButton) {
        syncLanUi();
        lanButton.addEventListener('click', async () => {
            const isLan = lanButton.getAttribute('data-is-lan') === 'true';
            await updateNetworkMode(isLan ? 'internet-test' : 'lan-only');
        });
    }

    document.addEventListener('click', (event) => {
        if (!ipSection || !ipSection.classList.contains('is-open')) return;
        if (event.target.closest('[data-ip-section="true"], [data-ip-toggle="true"]')) return;
        ipSection.classList.remove('is-open');
        syncIpButton();
    });

    updateHistoryButtons();
    syncIpButton();
    apply();
})();
    "#
}

fn profile_script() -> &'static str {
    r#"
(() => {
    window.WebsiteBuuSync?.boot();
    const syncClient = window.WebsiteBuuSync || null;
    const clientUi = window.WebsiteBuuClientUi || {
        isOffline: () => navigator.onLine === false,
        requireOnline: () => navigator.onLine !== false,
        showNotice: () => {},
    };
    // Hoisted reference so the + tab picker can open documents
    let openDocument = null;
    const panelRoots = Array.from(document.querySelectorAll('.panel-shell[data-panel], .overlay-panel[data-panel]'));
    const initialPanel = document.body?.getAttribute('data-initial-panel') || '';
    const reportRoot = document.querySelector('[data-profile-report-root="true"]');
    if (reportRoot) {
        const surface = reportRoot.querySelector('[data-profile-report-surface="true"]');
        const editButton = reportRoot.querySelector('[data-profile-report-edit="true"]');
        const downloadLink = reportRoot.querySelector('[data-profile-report-download="true"]');
        const ribbon = reportRoot.querySelector('[data-profile-report-ribbon="true"]');
        const tabsStrip = reportRoot.querySelector('[data-profile-report-tabs="true"]');
        const addTabButton = reportRoot.querySelector('[data-profile-report-add-tab="true"]');
        const searchToggle = reportRoot.querySelector('[data-profile-report-search-toggle="true"]');
        const searchBar = reportRoot.querySelector('[data-profile-report-search-bar="true"]');
        const searchInput = reportRoot.querySelector('[data-profile-report-search="true"]');
        const searchClose = reportRoot.querySelector('[data-profile-report-search-close="true"]');
        const searchCount = reportRoot.querySelector('[data-profile-report-search-count="true"]');
        const defaultReportName = tabsStrip?.getAttribute('data-report-default-name') || 'Bao_cao.docx';
        const reportTabs = new Map([['main', { name: defaultReportName, html: surface?.innerHTML || '' }]]);
        let activeReportTab = 'main';
        const reportDownloadUrl = (html) => {
            const blob = new Blob([`<!doctype html><html><head><meta charset="utf-8"></head><body>${html}</body></html>`], { type: 'application/msword;charset=utf-8' });
            return URL.createObjectURL(blob);
        };
        const syncActiveReport = () => {
            const record = reportTabs.get(activeReportTab);
            if (record && surface) {
                record.html = surface.innerHTML;
            }
        };
        const renderReportTabs = () => {
            if (!tabsStrip) return;
            const addButton = addTabButton;
            tabsStrip.innerHTML = '';
            reportTabs.forEach((record, tabId) => {
                const tab = document.createElement('div');
                tab.className = `profile-document-tab report-document-tab${tabId === activeReportTab ? ' is-active' : ''}`;
                tab.setAttribute('data-report-tab', 'true');
                tab.setAttribute('data-report-tab-id', tabId);

                const openButton = document.createElement('button');
                openButton.type = 'button';
                openButton.className = 'profile-document-tab-button';
                openButton.textContent = record.name;
                openButton.title = record.name;
                openButton.addEventListener('click', () => {
                    if (tabId === activeReportTab) return;
                    syncActiveReport();
                    activeReportTab = tabId;
                    if (surface) surface.innerHTML = reportTabs.get(tabId)?.html || '';
                    renderReportTabs();
                    applyReportSearch();
                });

                const closeButton = document.createElement('button');
                closeButton.type = 'button';
                closeButton.className = 'profile-document-tab-close';
                closeButton.textContent = '×';
                closeButton.title = 'Đóng tab';
                closeButton.addEventListener('click', () => {
                    if (reportTabs.size <= 1) return;
                    reportTabs.delete(tabId);
                    if (activeReportTab === tabId) {
                        activeReportTab = Array.from(reportTabs.keys()).at(-1) || 'main';
                        if (surface) surface.innerHTML = reportTabs.get(activeReportTab)?.html || '';
                    }
                    renderReportTabs();
                    applyReportSearch();
                });

                tab.append(openButton, closeButton);
                tabsStrip.appendChild(tab);
            });
            if (addButton) tabsStrip.appendChild(addButton);
        };
        const nextReportName = () => {
            if (!reportTabs.size) return defaultReportName;
            const dot = defaultReportName.lastIndexOf('.');
            const stem = dot > 0 ? defaultReportName.slice(0, dot) : defaultReportName;
            const ext = dot > 0 ? defaultReportName.slice(dot) : '.docx';
            return `${stem}_${reportTabs.size + 1}${ext}`;
        };
        addTabButton?.addEventListener('click', () => {
            syncActiveReport();
            const tabId = `report-${Date.now()}-${reportTabs.size}`;
            reportTabs.set(tabId, { name: nextReportName(), html: surface?.innerHTML || '' });
            activeReportTab = tabId;
            renderReportTabs();
            applyReportSearch();
        });
        let reportSearchMatches = [];
        let reportSearchIndex = -1;
        const collectReportMatches = (query) => {
            if (!surface || !query) return [];
            const matches = [];
            const walker = document.createTreeWalker(surface, NodeFilter.SHOW_TEXT);
            let node = walker.nextNode();
            while (node) {
                const text = node.nodeValue || '';
                const haystack = text.toLocaleLowerCase('vi-VN');
                let start = haystack.indexOf(query);
                while (start !== -1) {
                    matches.push({ node, start, end: start + query.length });
                    start = haystack.indexOf(query, start + query.length);
                }
                node = walker.nextNode();
            }
            return matches;
        };
        const selectReportMatch = (index) => {
            const match = reportSearchMatches[index];
            if (!match) return;
            const range = document.createRange();
            range.setStart(match.node, match.start);
            range.setEnd(match.node, match.end);
            const selection = window.getSelection();
            selection?.removeAllRanges();
            selection?.addRange(range);
            match.node.parentElement?.scrollIntoView({ block: 'center', behavior: 'smooth' });
        };
        const applyReportSearch = (next = false) => {
            if (!surface) return;
            const query = (searchInput?.value || '').trim().toLocaleLowerCase('vi-VN');
            if (!query) {
                reportSearchMatches = [];
                reportSearchIndex = -1;
                window.getSelection()?.removeAllRanges();
                if (searchCount) searchCount.textContent = '';
                return;
            }
            reportSearchMatches = collectReportMatches(query);
            if (!reportSearchMatches.length) {
                reportSearchIndex = -1;
                window.getSelection()?.removeAllRanges();
                if (searchCount) searchCount.textContent = '0 kết quả';
                return;
            }
            reportSearchIndex = next
                ? (reportSearchIndex + 1 + reportSearchMatches.length) % reportSearchMatches.length
                : 0;
            selectReportMatch(reportSearchIndex);
            if (searchCount) searchCount.textContent = `${reportSearchIndex + 1} / ${reportSearchMatches.length}`;
        };
        searchInput?.addEventListener('input', () => applyReportSearch());
        searchInput?.addEventListener('keydown', (event) => {
            if (event.key === 'Enter') {
                event.preventDefault();
                applyReportSearch(true);
            }
        });
        searchToggle?.addEventListener('click', () => {
            if (!searchBar || !searchInput) return;
            const shouldOpen = searchBar.hidden;
            searchBar.hidden = !shouldOpen;
            searchToggle.classList.toggle('is-active', shouldOpen);
            if (shouldOpen) {
                searchInput.focus();
                searchInput.select();
            } else {
                searchInput.value = '';
                applyReportSearch();
            }
        });
        searchClose?.addEventListener('click', () => {
            if (!searchBar || !searchInput) return;
            searchBar.hidden = true;
            searchToggle?.classList.remove('is-active');
            searchInput.value = '';
            applyReportSearch();
            searchToggle?.focus();
        });
        editButton?.addEventListener('click', (event) => {
            event.preventDefault();
            const editing = surface?.getAttribute('contenteditable') === 'true';
            syncActiveReport();
            surface?.setAttribute('contenteditable', editing ? 'false' : 'true');
            surface?.classList.toggle('is-editing', !editing);
            if (ribbon) ribbon.hidden = editing;
            editButton.textContent = editing ? '✎' : '✓';
            editButton.title = editing ? 'Chỉnh sửa báo cáo' : 'Xong';
            editButton.setAttribute('aria-label', editing ? 'Chỉnh sửa báo cáo' : 'Xong');
            if (!editing) surface?.focus();
        });
        ribbon?.querySelectorAll('[data-report-command]').forEach((button) => {
            button.addEventListener('click', async () => {
                const command = button.getAttribute('data-report-command') || '';
                if (command === 'copy' || command === 'cut') {
                    const selected = window.getSelection()?.toString() || '';
                    navigator.clipboard?.writeText(selected).catch(() => {});
                    if (command === 'copy') return;
                }
                if (command === 'paste') {
                    const text = await navigator.clipboard?.readText().catch(() => '');
                    document.execCommand('insertText', false, text);
                    syncActiveReport();
                    return;
                }
                document.execCommand(command, false, null);
                button.classList.toggle('is-active');
                syncActiveReport();
            });
        });
        ribbon?.querySelector('[data-report-font="true"]')?.addEventListener('change', (event) => {
            document.execCommand('fontName', false, event.target.value);
            syncActiveReport();
        });
        ribbon?.querySelector('[data-report-font-size="true"]')?.addEventListener('change', (event) => {
            document.execCommand('fontSize', false, '3');
            const selection = window.getSelection();
            const parent = selection?.anchorNode?.parentElement;
            if (parent) parent.style.fontSize = `${event.target.value}px`;
            syncActiveReport();
        });
        ribbon?.querySelector('[data-report-text-color="true"]')?.addEventListener('input', (event) => {
            document.execCommand('foreColor', false, event.target.value);
            syncActiveReport();
        });
        surface?.addEventListener('input', () => {
            syncActiveReport();
            applyReportSearch();
        });
        downloadLink?.addEventListener('click', () => {
            if (!surface || !downloadLink) return;
            syncActiveReport();
            downloadLink.download = reportTabs.get(activeReportTab)?.name || defaultReportName;
            downloadLink.href = reportDownloadUrl(surface.innerHTML);
        });
        renderReportTabs();
    }
    const clearPanelQueryState = () => {
        const url = new URL(window.location.href);
        const changed = url.searchParams.has('panel') || url.searchParams.has('chat');
        if (!changed) return;
        url.searchParams.delete('panel');
        url.searchParams.delete('chat');
        const nextUrl = `${url.pathname}${url.search}${url.hash}`;
        window.history.replaceState(window.history.state, '', nextUrl);
        document.body?.setAttribute('data-initial-panel', '');
    };
    const syncCompactPanels = () => {
        document.querySelectorAll('.panel-shell').forEach((panel) => {
            const compactPanel = Array.from(panel.children).find((child) => child.classList && child.classList.contains('compact-panel'));
            if (!compactPanel) return;
            compactPanel.style.setProperty('display', panel.classList.contains('is-open') ? 'grid' : 'none', 'important');
        });
    };
    const closePanels = (exceptName = null) => {
        panelRoots.forEach((panel) => {
            const name = panel.getAttribute('data-panel');
            panel.classList.toggle('is-open', !!exceptName && name === exceptName);
        });
        syncCompactPanels();
        if (exceptName !== 'chat') {
            clearPanelQueryState();
        }
    };

    document.querySelectorAll('[data-panel-toggle]').forEach((button) => {
        button.addEventListener('click', (event) => {
            event.preventDefault();
            event.stopPropagation();
            if (button.getAttribute('data-requires-online') === 'true' && !clientUi.requireOnline()) {
                return;
            }
            const target = button.getAttribute('data-panel-toggle');
            const panel = document.querySelector(`.panel-shell[data-panel="${target}"], .overlay-panel[data-panel="${target}"]`);
            if (!panel) return;
            const shouldOpen = !panel.classList.contains('is-open');
            closePanels(shouldOpen ? target : null);
        });
    });

    document.addEventListener('click', (event) => {
        const inside = event.target.closest('.panel-shell, .overlay-card, [data-panel-toggle]');
        if (!inside) closePanels();
    });

    const rememberProfileBackTarget = (target) => {
        try {
            window.sessionStorage.setItem('website_buu.profileBackTarget', target);
        } catch (_) {}
    };

    document.querySelectorAll('a.dashboard-action-button[href^="/units/"], a.tree-node-link[href^="/units/"]').forEach((link) => {
        link.addEventListener('click', () => {
            rememberProfileBackTarget('/');
        });
    });

    document.querySelectorAll('[data-profile-upload-input="true"]').forEach((input) => {
        input.addEventListener('change', () => {
            const file = input.files && input.files[0];
            if (!file) {
                return;
            }
            const form = input.closest('[data-profile-upload-form="true"]');
            if (!form) {
                return;
            }
            const titleInput = form.querySelector('[data-profile-upload-title="true"]');
            const kind = form.getAttribute('data-profile-upload-kind') || 'unit';
            const rawName = String(file.name || '').replace(/\.[^.]+$/, '').trim();
            const baseName = rawName || 'tai-lieu';
            if (titleInput) {
                titleInput.value = kind === 'shared' ? `Tài liệu đồng bộ ${baseName}` : baseName;
            }
            form.requestSubmit();
        });
    });

    const backButton = document.querySelector('[data-go-back="true"]');
    if (backButton) {
        backButton.addEventListener('click', () => {
            const returnTarget = (() => {
                try {
                    const params = new URLSearchParams(window.location.search);
                    return params.get('return_to') || '';
                } catch (_) {
                    return '';
                }
            })();
            let stableTarget = '';
            try {
                stableTarget = window.sessionStorage.getItem('website_buu.profileBackTarget') || '';
            } catch (_) {}

            if (returnTarget && returnTarget !== window.location.pathname) {
                window.location.href = returnTarget;
            } else if (stableTarget && stableTarget !== window.location.pathname) {
                window.location.href = stableTarget;
            } else if (window.history.length > 1) {
                window.history.back();
            } else {
                window.location.href = '/';
            }
        });
    }

    if (initialPanel) {
        requestAnimationFrame(() => closePanels(initialPanel));
    } else {
        closePanels();
    }

    const profileDocRoot = document.querySelector('[data-profile-doc-root="true"]');
    if (profileDocRoot) {
        const recordsNode = profileDocRoot.querySelector('[data-profile-doc-records="true"]');
        let records = [];
        try {
            records = JSON.parse(recordsNode?.textContent || '[]');
        } catch (_) {
            records = [];
        }

        const docs = new Map(records.map((item) => [item.id, { ...item }]));
        const defaultDocId = profileDocRoot.getAttribute('data-default-doc-id') || records[0]?.id || '';
        const selectedDocId = profileDocRoot.getAttribute('data-selected-doc-id') || '';
        const canEdit = profileDocRoot.getAttribute('data-can-edit') === 'true';
        const unitIsLeaf = profileDocRoot.getAttribute('data-unit-is-leaf') === 'true';
        const unitId = profileDocRoot.getAttribute('data-unit-id') || '';
        const tabsStrip = profileDocRoot.querySelector('[data-profile-doc-tabs="true"]');
        const grid = profileDocRoot.querySelector('[data-profile-doc-grid="true"]');
        const editToggle = profileDocRoot.querySelector('[data-profile-doc-edit-toggle="true"]');
        const addRowButton = profileDocRoot.querySelector('[data-profile-doc-add-row="true"]');
        const addColButton = profileDocRoot.querySelector('[data-profile-doc-add-col="true"]');
        const fontSelect = profileDocRoot.querySelector('[data-profile-doc-font="true"]');
        const boldButton = profileDocRoot.querySelector('[data-profile-doc-bold="true"]');
        const italicButton = profileDocRoot.querySelector('[data-profile-doc-italic="true"]');
        const saveForm = profileDocRoot.querySelector('[data-profile-doc-save-form="true"]');
        const savePayload = profileDocRoot.querySelector('[data-profile-doc-payload="true"]');
        const saveButton = profileDocRoot.querySelector('[data-profile-doc-save="true"]');
        const searchToggle = profileDocRoot.querySelector('[data-profile-doc-search-toggle="true"]');
        const kindToggle = profileDocRoot.querySelector('[data-profile-doc-kind-toggle="true"]');
        const kindButtons = Array.from(document.querySelectorAll('[data-profile-doc-kind-button]'));
        const searchBar = profileDocRoot.querySelector('[data-profile-doc-search-bar="true"]');
        const searchClose = profileDocRoot.querySelector('[data-profile-doc-search-close="true"]');
        const csrfToken = profileDocRoot.getAttribute('data-profile-doc-csrf') || '';
        const linkedDocuments = Array.from(document.querySelectorAll('[data-profile-doc-open]'));
        const searchInput = profileDocRoot.querySelector('[data-profile-doc-search="true"]');
        const searchCountEl = profileDocRoot.querySelector('[data-profile-doc-search-count="true"]');
        let openTabs = [];
        let activeDocId = '';
        let editMode = false;
        let activeCell = null;
        const drafts = new Map();
        let saveInFlight = false;
        let autoSaveTimer = null;

        const activeDocRecord = () => (activeDocId ? docs.get(activeDocId) || null : null);

        const shortenName = (fileName) => {
            const clean = String(fileName || '').trim();
            const chars = Array.from(clean);
            if (chars.length <= 12) return clean;
            return chars.slice(0, 12).join('');
        };

        const columnName = (index) => {
            let value = index + 1;
            let label = '';
            while (value > 0) {
                const remainder = (value - 1) % 26;
                label = String.fromCharCode(65 + remainder) + label;
                value = Math.floor((value - 1) / 26);
            }
            return label;
        };

        const columnPixelWidth = (rows, colIndex) => {
            const maxLen = rows.reduce((longest, row) => {
                const value = String(row[colIndex] ?? '');
                return Math.max(longest, Array.from(value).length);
            }, 0);
            const firstValue = String(rows[0]?.[colIndex] ?? '').trim().toLowerCase();
            if (firstValue === 'stt') return 58;
            return Math.max(90, Math.min(360, (maxLen * 8) + 28));
        };

        const unescapeSheetCell = (value) => String(value ?? '').replace(/\\(n|t|r|\\)/g, (_, marker) => {
            if (marker === 'n') return '\n';
            if (marker === 't') return '\t';
            if (marker === 'r') return '\r';
            return '\\';
        });

        const escapeSheetCell = (value) => String(value ?? '')
            .replace(/\\/g, '\\\\')
            .replace(/\r\n/g, '\n')
            .replace(/\r/g, '\n')
            .replace(/\n/g, '\\n')
            .replace(/\t/g, '\\t');

        const normalizeSheetHeader = (value) => String(value ?? '')
            .trim()
            .toLowerCase()
            .normalize('NFD')
            .replace(/[\u0300-\u036f]/g, '')
            .replace(/đ/g, 'd')
            .replace(/[^a-z0-9]/g, '');

        const parseSheet = (text) => {
            const normalized = String(text || '').replace(/\r\n/g, '\n').replace(/\r/g, '\n');
            const sourceRows = normalized.length ? normalized.split('\n') : [''];
            const hasTabs = sourceRows.some((row) => row.includes('\t'));
            const hasComma = sourceRows.some((row) => row.includes(','));
            const hasSemicolon = sourceRows.some((row) => row.includes(';'));
            const delimiter = hasTabs ? '\t' : (hasComma ? ',' : (hasSemicolon ? ';' : '\t'));
            let rows = sourceRows.map((row) => {
                if (!row.length) {
                    return [''];
                }
                return ((hasTabs || hasComma || hasSemicolon) ? row.split(delimiter) : [row]).map(unescapeSheetCell);
            });
            const width = Math.max(1, ...rows.map((row) => row.length));
            rows = rows.map((row) => Array.from({ length: width }, (_, index) => row[index] ?? ''));
            return rows;
        };

        const serializeRows = (rows) => rows.map((row) => row.map(escapeSheetCell).join('\t')).join('\n');

        const currentSerializedPreview = () => {
            const draft = ensureDraft(activeDocId);
            if (!draft) {
                return '';
            }
            return serializeRows(draft.rows);
        };

        const ensureDraft = (docId) => {
            if (!docId || !docs.has(docId)) {
                return null;
            }
            if (!drafts.has(docId)) {
                const doc = docs.get(docId);
                drafts.set(docId, {
                    rows: parseSheet(doc.preview_text),
                    dirty: false,
                });
            }
            return drafts.get(docId);
        };

        const syncSaveForm = () => {
            if (!saveForm || !savePayload || !activeDocId) {
                return;
            }
            const doc = activeDocRecord();
            const draft = ensureDraft(activeDocId);
            if (!draft || !doc) {
                return;
            }
            saveForm.action = `/units/${encodeURIComponent(unitId)}/documents/${encodeURIComponent(activeDocId)}`;
            savePayload.value = serializeRows(draft.rows);
            const docEditable = canEdit && !!doc.editable;
            const activeKind = doc.kind === 'internal' ? 'internal' : 'synced';
            if (editToggle) {
                editToggle.hidden = !canEdit;
                editToggle.classList.toggle('is-disabled', !docEditable);
                editToggle.textContent = editMode ? '✓' : '✎';
                editToggle.title = docEditable
                    ? (editMode ? 'Kết thúc chỉnh sửa và lưu' : 'Chỉnh sửa và kiểm tra chính tả')
                    : 'Tài liệu này chỉ xem, không chỉnh sửa được';
                editToggle.setAttribute('aria-label', editToggle.title);
            }
            kindButtons.forEach((button) => {
                const buttonKind = button.getAttribute('data-profile-doc-kind-button') || '';
                button.classList.toggle('is-active', buttonKind === activeKind);
            });
            if (kindToggle) {
                const targetKind = activeKind === 'synced' ? 'internal' : 'synced';
                const hasTargetKind = Array.from(docs.values()).some((item) => item.kind === targetKind);
                kindToggle.textContent = targetKind === 'internal' ? 'NB' : 'ĐB';
                kindToggle.title = targetKind === 'internal'
                    ? 'Chuyển về Tài liệu nội bộ'
                    : 'Chuyển về Tài liệu đồng bộ';
                kindToggle.setAttribute('aria-label', kindToggle.title);
                kindToggle.disabled = !hasTargetKind;
            }
        };

        const renderTabs = () => {
            if (!tabsStrip) {
                return;
            }
            const addShell = tabsStrip.querySelector('[data-doc-add-shell="true"]');
            tabsStrip.innerHTML = '';
            openTabs.forEach((docId) => {
                const doc = docs.get(docId);
                if (!doc) {
                    return;
                }
                const tab = document.createElement('div');
                tab.className = `profile-document-tab${docId === activeDocId ? ' is-active' : ''}`;

                const openButton = document.createElement('button');
                openButton.type = 'button';
                openButton.className = 'profile-document-tab-button';
                openButton.textContent = shortenName(doc.file_name);
                openButton.title = doc.file_name;
                openButton.addEventListener('click', () => {
                    activeDocId = docId;
                    renderTabs();
                    renderGrid();
                });

                const closeButton = document.createElement('button');
                closeButton.type = 'button';
                closeButton.className = 'profile-document-tab-close';
                closeButton.textContent = '×';
                closeButton.title = 'Đóng tab';
                closeButton.addEventListener('click', () => {
                    openTabs = openTabs.filter((item) => item !== docId);
                    if (!openTabs.length && defaultDocId) {
                        openTabs = [defaultDocId];
                    }
                    if (!openTabs.includes(activeDocId)) {
                        activeDocId = openTabs[openTabs.length - 1] || defaultDocId;
                    }
                    renderTabs();
                    renderGrid();
                });

                tab.append(openButton, closeButton);
                tabsStrip.appendChild(tab);
            });
            if (addShell) tabsStrip.appendChild(addShell);
        };

        const applyDocSearch = () => {
            if (!grid) return;
            const query = (searchInput?.value || '').trim().toLowerCase();
            const rows = Array.from(grid.querySelectorAll('tbody tr'));
            let matched = 0;
            rows.forEach((row) => {
                if (!query) {
                    row.classList.remove('xl-search-hidden');
                    matched += 1;
                } else {
                    const text = Array.from(row.querySelectorAll('td'))
                        .map((td) => td.textContent || '')
                        .join(' ')
                        .toLowerCase();
                    const visible = text.includes(query);
                    row.classList.toggle('xl-search-hidden', !visible);
                    if (visible) matched += 1;
                }
            });
            if (searchCountEl) {
                searchCountEl.textContent = query ? `${matched} / ${rows.length} hàng` : '';
            }
        };

        if (searchInput) {
            searchInput.addEventListener('input', applyDocSearch);
        }

        if (searchToggle && searchBar && searchInput) {
            searchToggle.addEventListener('click', () => {
                const shouldOpen = searchBar.hidden;
                searchBar.hidden = !shouldOpen;
                searchToggle.classList.toggle('is-active', shouldOpen);
                if (shouldOpen) {
                    searchInput.focus();
                    searchInput.select();
                } else {
                    searchInput.value = '';
                    applyDocSearch();
                }
            });
        }

        if (searchClose && searchBar && searchInput) {
            searchClose.addEventListener('click', () => {
                searchBar.hidden = true;
                searchToggle?.classList.remove('is-active');
                searchInput.value = '';
                applyDocSearch();
                searchToggle?.focus();
            });
        }

        if (kindToggle) {
            kindToggle.addEventListener('click', () => {
                const activeDoc = activeDocRecord();
                const activeKind = activeDoc?.kind === 'internal' ? 'internal' : 'synced';
                const targetKind = activeKind === 'synced' ? 'internal' : 'synced';
                const targetDoc = Array.from(docs.values()).find((item) => item.kind === targetKind);
                if (targetDoc) {
                    openDocument?.(targetDoc.id, true);
                }
            });
        }

        function renderGrid() {
            if (!grid || !activeDocId) {
                return;
            }
            const doc = docs.get(activeDocId);
            const draft = ensureDraft(activeDocId);
            if (!doc || !draft) {
                return;
            }
            const docEditable = canEdit && !!doc.editable;

            const width = Math.max(1, ...draft.rows.map((row) => row.length));
            draft.rows = draft.rows.map((row) => Array.from({ length: width }, (_, index) => row[index] ?? ''));
            const columnWidths = Array.from({ length: width }, (_, colIndex) => columnPixelWidth(draft.rows, colIndex));
            const activityColIndex = draft.rows[0]?.findIndex((cell) => normalizeSheetHeader(cell) === 'hoatdongcuadonvi') ?? -1;
            const activityRowSpan = activityColIndex >= 0 && draft.rows.length > 1
                ? Math.max(1, draft.rows.length - 1)
                : 1;

            const thead = document.createElement('thead');
            const headRow = document.createElement('tr');
            for (let col = 0; col < width; col += 1) {
                const th = document.createElement('th');
                th.textContent = columnName(col);
                th.style.width = `${columnWidths[col]}px`;
                th.style.minWidth = `${columnWidths[col]}px`;
                headRow.appendChild(th);
            }
            thead.appendChild(headRow);

            const tbody = document.createElement('tbody');
            draft.rows.forEach((row, rowIndex) => {
                const tr = document.createElement('tr');
                tr.classList.toggle('is-data-header', rowIndex === 0);
                row.forEach((cell, colIndex) => {
                    if (activityColIndex === colIndex && rowIndex > 1) {
                        return;
                    }
                    const td = document.createElement('td');
                    td.dataset.rowIndex = String(rowIndex);
                    td.dataset.colIndex = String(colIndex);
                    td.textContent = cell;
                    if (activityColIndex === colIndex && rowIndex === 1 && activityRowSpan > 1) {
                        td.rowSpan = activityRowSpan;
                        td.classList.add('xl-unit-activity-cell');
                    }
                    td.contentEditable = String(docEditable && editMode);
                    td.classList.toggle('is-editing', docEditable && editMode);
                    td.style.width = `${columnWidths[colIndex]}px`;
                    td.style.minWidth = `${columnWidths[colIndex]}px`;
                    tr.appendChild(td);
                });
                tbody.appendChild(tr);
            });

            grid.innerHTML = '';
            grid.append(thead, tbody);
            syncSaveForm();
            applyDocSearch();
            applySpellcheck();
        }

        const updateDraftFromGrid = () => {
            const draft = ensureDraft(activeDocId);
            if (!draft || !grid) {
                return;
            }
            const width = Math.max(1, ...draft.rows.map((row) => row.length));
            const rows = Array.from(grid.querySelectorAll('tbody tr')).map((row) => {
                const values = Array.from({ length: width }, () => '');
                Array.from(row.querySelectorAll('td')).forEach((cell, fallbackIndex) => {
                    const colIndex = Number(cell.dataset.colIndex ?? fallbackIndex);
                    if (Number.isInteger(colIndex) && colIndex >= 0 && colIndex < width) {
                        values[colIndex] = cell.textContent || '';
                    }
                });
                return values;
            });
            draft.rows = rows.length ? rows : [['']];
            draft.dirty = true;
            syncSaveForm();
        };

        const saveActiveDocument = async ({ silent = false } = {}) => {
            updateDraftFromGrid();
            const doc = activeDocRecord();
            if (!doc?.editable || !savePayload || !saveForm || !activeDocId || !syncClient?.buildFormRequest || !syncClient?.submitServerAction) {
                return false;
            }
            if (saveInFlight) {
                return false;
            }
            saveInFlight = true;
            saveButton?.setAttribute('disabled', 'disabled');
            const submittedPreview = savePayload.value;
            try {
                const result = await syncClient.submitServerAction({
                    type: 'profile-document-save',
                    request: syncClient.buildFormRequest(saveForm, { accept: 'text/html,application/xhtml+xml' }),
                    responseType: 'text',
                    queueMessage: 'Đã lưu nội dung vào hàng đợi, sẽ đồng bộ khi online.',
                });
                if (!result?.ok) {
                    if (!silent) clientUi.showNotice('Không lưu được tài liệu.', 'error');
                    return false;
                }
                const draft = ensureDraft(activeDocId);
                if (draft) {
                    draft.dirty = currentSerializedPreview() !== submittedPreview;
                }
                const activeDoc = docs.get(activeDocId);
                if (activeDoc) {
                    activeDoc.preview_text = submittedPreview;
                }
                if (!silent) {
                    clientUi.showNotice(result.queued ? 'Đã lưu nội dung chờ đồng bộ.' : 'Đã lưu tài liệu.', 'success');
                }
                return true;
            } finally {
                saveInFlight = false;
                saveButton?.removeAttribute('disabled');
            }
        };

        const scheduleAutoSave = () => {
            if (autoSaveTimer) {
                window.clearTimeout(autoSaveTimer);
            }
            autoSaveTimer = window.setTimeout(() => {
                autoSaveTimer = null;
                const draft = ensureDraft(activeDocId);
                const doc = activeDocRecord();
                if (editMode && draft?.dirty && doc?.editable) {
                    saveActiveDocument({ silent: true });
                }
            }, 5000);
        };

        const markSheetChanged = () => {
            const draft = ensureDraft(activeDocId);
            if (draft) {
                draft.dirty = true;
            }
            syncSaveForm();
            scheduleAutoSave();
        };

        openDocument = (docId, activate = true) => {
            if (!docId || !docs.has(docId)) {
                return;
            }
            if (!openTabs.includes(docId)) {
                openTabs.push(docId);
            }
            if (activate) {
                activeDocId = docId;
            }
            renderTabs();
            renderGrid();
            closePanels();
            window.history.replaceState({}, '', `/units/${encodeURIComponent(unitId)}?doc=${encodeURIComponent(activeDocId)}`);
            // update download link
            const dlLink = profileDocRoot.querySelector('[data-profile-doc-download-link="true"]');
            if (dlLink) dlLink.href = `/units/${encodeURIComponent(unitId)}/documents/${encodeURIComponent(activeDocId)}/download`;
        };

        grid?.addEventListener('focusin', (event) => {
            activeCell = event.target?.closest ? event.target.closest('td[data-row-index][data-col-index]') : null;
        });

        grid?.addEventListener('input', (event) => {
            const cell = event.target?.closest ? event.target.closest('td[data-row-index][data-col-index]') : null;
            if (!cell || !editMode) {
                return;
            }
            const draft = ensureDraft(activeDocId);
            if (!draft) {
                return;
            }
            const rowIndex = Number(cell.dataset.rowIndex || '0');
            const colIndex = Number(cell.dataset.colIndex || '0');
            if (!draft.rows[rowIndex]) {
                draft.rows[rowIndex] = [];
            }
            draft.rows[rowIndex][colIndex] = cell.textContent || '';
            draft.dirty = true;
            syncSaveForm();
            scheduleAutoSave();
        });

        const ribbon = profileDocRoot.querySelector('[data-profile-doc-ribbon="true"]');

        const setDocumentEditMode = async (enabled, { save = false } = {}) => {
            const doc = activeDocRecord();
            if (enabled && !doc?.editable) {
                return;
            }
            const wasEditing = editMode;
            editMode = !!enabled;
            spellcheckActive = editMode;
            if (ribbon) ribbon.hidden = !editMode;
            editToggle?.classList.toggle('is-active', editMode);
            syncSaveForm();
            renderGrid();
            if (!enabled && save && wasEditing) {
                const draft = ensureDraft(activeDocId);
                if (draft?.dirty || wasEditing) {
                    saveActiveDocument({ silent: true });
                }
            }
        };

        if (editToggle && canEdit) {
            editToggle.addEventListener('click', async (event) => {
                event.preventDefault();
                event.stopPropagation();
                const doc = activeDocRecord();
                if (!doc?.editable) {
                    return;
                }
                await setDocumentEditMode(!editMode, { save: editMode });
            });
        }

        document.addEventListener('pointerdown', (event) => {
            if (!editMode) {
                return;
            }
            const target = event.target;
            if (grid?.contains(target) || ribbon?.contains(target) || editToggle?.contains(target)) {
                return;
            }
            setDocumentEditMode(false, { save: true });
        });

        // ── Excel ribbon handlers ──

        const applyToCell = (fn) => { if (activeCell) { fn(activeCell); } };

        addRowButton?.addEventListener('click', () => {
            const draft = ensureDraft(activeDocId);
            if (!draft) return;
            const width = Math.max(1, ...draft.rows.map((row) => row.length));
            const insertAt = activeCell ? Number(activeCell.dataset.rowIndex) + 1 : draft.rows.length;
            draft.rows.splice(insertAt, 0, Array.from({ length: width }, () => ''));
            renderGrid();
            markSheetChanged();
        });

        addColButton?.addEventListener('click', () => {
            const draft = ensureDraft(activeDocId);
            if (!draft) return;
            const insertAt = activeCell ? Number(activeCell.dataset.colIndex) + 1 : draft.rows[0]?.length ?? 1;
            draft.rows = draft.rows.map((row) => { const r = [...row]; r.splice(insertAt, 0, ''); return r; });
            renderGrid();
            markSheetChanged();
        });

        ribbon?.querySelector('[data-xl-del-row="true"]')?.addEventListener('click', () => {
            const draft = ensureDraft(activeDocId);
            if (!draft || draft.rows.length <= 1) return;
            const rowIndex = activeCell ? Number(activeCell.dataset.rowIndex) : draft.rows.length - 1;
            draft.rows.splice(rowIndex, 1);
            renderGrid();
            markSheetChanged();
        });

        ribbon?.querySelector('[data-xl-del-col="true"]')?.addEventListener('click', () => {
            const draft = ensureDraft(activeDocId);
            if (!draft || (draft.rows[0]?.length ?? 0) <= 1) return;
            const colIndex = activeCell ? Number(activeCell.dataset.colIndex) : (draft.rows[0]?.length ?? 1) - 1;
            draft.rows = draft.rows.map((row) => { const r = [...row]; r.splice(colIndex, 1); return r; });
            renderGrid();
            markSheetChanged();
        });

        fontSelect?.addEventListener('change', () => applyToCell((c) => { c.style.fontFamily = fontSelect.value; }));

        ribbon?.querySelector('[data-xl-font-size="true"]')?.addEventListener('change', (e) => {
            applyToCell((c) => { c.style.fontSize = e.target.value + 'px'; });
        });

        boldButton?.addEventListener('click', () => applyToCell((c) => {
            c.style.fontWeight = c.style.fontWeight === '700' ? '' : '700';
            boldButton.classList.toggle('is-active', c.style.fontWeight === '700');
        }));

        italicButton?.addEventListener('click', () => applyToCell((c) => {
            c.style.fontStyle = c.style.fontStyle === 'italic' ? '' : 'italic';
            italicButton.classList.toggle('is-active', c.style.fontStyle === 'italic');
        }));

        ribbon?.querySelector('[data-xl-underline="true"]')?.addEventListener('click', function() {
            applyToCell((c) => {
                const on = c.style.textDecoration.includes('underline');
                c.style.textDecoration = on ? c.style.textDecoration.replace('underline','').trim() : (c.style.textDecoration + ' underline').trim();
                this.classList.toggle('is-active', !on);
            });
        });

        ribbon?.querySelector('[data-xl-strikethrough="true"]')?.addEventListener('click', function() {
            applyToCell((c) => {
                const on = c.style.textDecoration.includes('line-through');
                c.style.textDecoration = on ? c.style.textDecoration.replace('line-through','').trim() : (c.style.textDecoration + ' line-through').trim();
                this.classList.toggle('is-active', !on);
            });
        });

        ribbon?.querySelector('[data-xl-text-color="true"]')?.addEventListener('input', (e) => {
            applyToCell((c) => { c.style.color = e.target.value; });
        });

        ribbon?.querySelector('[data-xl-fill-color="true"]')?.addEventListener('input', (e) => {
            applyToCell((c) => { c.style.backgroundColor = e.target.value; });
        });

        ribbon?.querySelectorAll('[data-xl-align]').forEach((btn) => {
            btn.addEventListener('click', () => {
                const align = btn.getAttribute('data-xl-align');
                applyToCell((c) => { c.style.textAlign = align; });
                ribbon.querySelectorAll('[data-xl-align]').forEach((b) => b.classList.remove('is-active'));
                btn.classList.add('is-active');
            });
        });

        ribbon?.querySelectorAll('[data-xl-valign]').forEach((btn) => {
            btn.addEventListener('click', () => {
                const valign = btn.getAttribute('data-xl-valign');
                const cssMap = { top: 'top', middle: 'middle', bottom: 'bottom' };
                applyToCell((c) => { c.style.verticalAlign = cssMap[valign] || 'middle'; });
                ribbon.querySelectorAll('[data-xl-valign]').forEach((b) => b.classList.remove('is-active'));
                btn.classList.add('is-active');
            });
        });

        ribbon?.querySelector('[data-xl-wrap-text="true"]')?.addEventListener('click', function() {
            applyToCell((c) => {
                const wrapping = c.style.whiteSpace === 'pre-wrap' || !c.style.whiteSpace;
                c.style.whiteSpace = wrapping ? 'nowrap' : 'pre-wrap';
                this.classList.toggle('is-active', !wrapping);
            });
        });

        ribbon?.querySelector('[data-xl-num-format="true"]')?.addEventListener('change', (e) => {
            applyToCell((c) => {
                const fmt = e.target.value;
                const raw = c.textContent;
                const num = parseFloat(raw.replace(/[^0-9.-]/g,''));
                if (isNaN(num)) return;
                const formatted = {
                    number: num.toLocaleString('vi-VN'),
                    currency: num.toLocaleString('vi-VN', { style: 'currency', currency: 'VND' }),
                    percent: (num / 100).toLocaleString('vi-VN', { style: 'percent', maximumFractionDigits: 2 }),
                    date: new Date(raw).toLocaleDateString('vi-VN'),
                    text: raw,
                }[fmt] || raw;
                c.textContent = formatted;
            });
        });

        ribbon?.querySelector('[data-xl-format-currency="true"]')?.addEventListener('click', () => {
            applyToCell((c) => {
                const n = parseFloat(c.textContent.replace(/[^0-9.-]/g,''));
                if (!isNaN(n)) c.textContent = n.toLocaleString('vi-VN', { style: 'currency', currency: 'VND' });
            });
        });

        ribbon?.querySelector('[data-xl-format-percent="true"]')?.addEventListener('click', () => {
            applyToCell((c) => {
                const n = parseFloat(c.textContent.replace(/[^0-9.%-]/g,'').replace('%',''));
                if (!isNaN(n)) c.textContent = (n / 100).toLocaleString('vi-VN', { style: 'percent' });
            });
        });

        ribbon?.querySelector('[data-xl-format-comma="true"]')?.addEventListener('click', () => {
            applyToCell((c) => {
                const n = parseFloat(c.textContent.replace(/[^0-9.-]/g,''));
                if (!isNaN(n)) c.textContent = n.toLocaleString('vi-VN');
            });
        });

        ribbon?.querySelector('[data-xl-increase-decimal="true"]')?.addEventListener('click', () => {
            applyToCell((c) => {
                const n = parseFloat(c.textContent.replace(/[^0-9.-]/g,''));
                if (!isNaN(n)) {
                    const cur = (c.textContent.split('.')[1] || '').length;
                    c.textContent = n.toFixed(cur + 1);
                }
            });
        });

        ribbon?.querySelector('[data-xl-decrease-decimal="true"]')?.addEventListener('click', () => {
            applyToCell((c) => {
                const n = parseFloat(c.textContent.replace(/[^0-9.-]/g,''));
                if (!isNaN(n)) {
                    const cur = Math.max(0, (c.textContent.split('.')[1] || '').length);
                    c.textContent = n.toFixed(Math.max(0, cur - 1));
                }
            });
        });

        ribbon?.querySelector('[data-xl-sort-asc="true"]')?.addEventListener('click', () => {
            const draft = ensureDraft(activeDocId);
            if (!draft || draft.rows.length < 2) return;
            const col = activeCell ? Number(activeCell.dataset.colIndex) : 0;
            const header = draft.rows[0];
            const body = draft.rows.slice(1).sort((a, b) => String(a[col]??'').localeCompare(String(b[col]??''), 'vi'));
            draft.rows = [header, ...body];
            renderGrid();
            markSheetChanged();
        });

        ribbon?.querySelector('[data-xl-sort-desc="true"]')?.addEventListener('click', () => {
            const draft = ensureDraft(activeDocId);
            if (!draft || draft.rows.length < 2) return;
            const col = activeCell ? Number(activeCell.dataset.colIndex) : 0;
            const header = draft.rows[0];
            const body = draft.rows.slice(1).sort((a, b) => String(b[col]??'').localeCompare(String(a[col]??''), 'vi'));
            draft.rows = [header, ...body];
            renderGrid();
            markSheetChanged();
        });

        ribbon?.querySelector('[data-xl-clear="true"]')?.addEventListener('click', () => {
            applyToCell((c) => { c.textContent = ''; c.removeAttribute('style'); });
            updateDraftFromGrid();
            markSheetChanged();
        });

        ribbon?.querySelector('[data-xl-cut="true"]')?.addEventListener('click', () => {
            if (!activeCell) return;
            navigator.clipboard?.writeText(activeCell.textContent || '').catch(() => {});
            activeCell.textContent = '';
            updateDraftFromGrid();
            markSheetChanged();
        });

        ribbon?.querySelector('[data-xl-copy="true"]')?.addEventListener('click', () => {
            if (activeCell) navigator.clipboard?.writeText(activeCell.textContent || '').catch(() => {});
        });

        ribbon?.querySelector('[data-xl-paste="true"]')?.addEventListener('click', async () => {
            if (!activeCell) return;
            const text = await navigator.clipboard?.readText().catch(() => '');
            if (text !== undefined) {
                activeCell.textContent = text;
                updateDraftFromGrid();
                markSheetChanged();
            }
        });

        ribbon?.querySelector('[data-xl-border="all"]')?.addEventListener('click', () => {
            applyToCell((c) => { c.style.border = '1px solid rgba(105,244,207,0.4)'; });
        });
        ribbon?.querySelector('[data-xl-border="outer"]')?.addEventListener('click', () => {
            applyToCell((c) => { c.style.outline = '1px solid rgba(105,244,207,0.4)'; c.style.border = ''; });
        });
        ribbon?.querySelector('[data-xl-border="none"]')?.addEventListener('click', () => {
            applyToCell((c) => { c.style.border = 'none'; c.style.outline = ''; });
        });

        ribbon?.querySelector('[data-xl-merge="true"]')?.addEventListener('click', () => {
            // Simple: mark cell with colspan visual hint
            applyToCell((c) => { c.colSpan = c.colSpan > 1 ? 1 : 2; });
        });

        // Download link update when tab changes
        const downloadLink = profileDocRoot.querySelector('[data-profile-doc-download-link="true"]');

        saveForm?.addEventListener('submit', async (event) => {
            event.preventDefault();
            await saveActiveDocument({ silent: false });
        });

        window.setInterval(() => {
            const draft = ensureDraft(activeDocId);
            const doc = activeDocRecord();
            if (!editMode || !draft?.dirty || !doc?.editable || saveInFlight) {
                return;
            }
            saveActiveDocument({ silent: true });
        }, 10 * 60 * 1000);

        // Spellcheck toggle
        let spellcheckActive = false;
        const applySpellcheck = () => {
            if (!grid) return;
            grid.querySelectorAll('td').forEach((td) => {
                td.spellcheck = spellcheckActive;
                td.lang = spellcheckActive ? 'vi' : '';
            });
        };
        // Keyboard shortcut Ctrl+S to save
        document.addEventListener('keydown', (e) => {
            if ((e.ctrlKey || e.metaKey) && e.key === 's' && editMode) {
                e.preventDefault();
                saveForm?.requestSubmit?.() || saveForm?.submit?.();
            }
        });

        linkedDocuments.forEach((link) => {
            link.addEventListener('click', (event) => {
                const docId = link.getAttribute('data-profile-doc-open') || '';
                if (!docId || !docs.has(docId)) {
                    return;
                }
                event.preventDefault();
                openDocument(docId, true);
            });
        });

        window.WebsiteBuuProfileDocsSync = {
            applyDocuments(updatedDocuments) {
                let rerender = false;
                updatedDocuments.forEach((document) => {
                    if (!docs.has(document.id)) {
                        return;
                    }
                    const current = docs.get(document.id);
                    current.file_name = document.file_name || current.file_name;
                    current.mime_type = document.mime_type || current.mime_type;
                    current.preview_text = document.preview_text;
                    current.updated_at = document.updated_at || '';
                    const draft = drafts.get(document.id);
                    if (!draft || !draft.dirty) {
                        drafts.delete(document.id);
                        if (document.id === activeDocId) {
                            rerender = true;
                        }
                    }
                });
                renderTabs();
                if (rerender) {
                    renderGrid();
                }
            },
        };

        if (defaultDocId) {
            openDocument(defaultDocId, true);
        }
        if (selectedDocId && selectedDocId !== defaultDocId) {
            openDocument(selectedDocId, true);
        }
    }

    // ── Shared document list controls (⋮ menu, method selector, sync) ──
    const closeAllDocMenus = () => {
        document.querySelectorAll('[data-doc-bar]').forEach((m) => { m.hidden = true; });
    };
    const closeAllMethodMenus = () => {
        document.querySelectorAll('[data-doc-method-menu]').forEach((m) => { m.hidden = true; });
    };
    const DEFAULT_SHARED_METHOD = 'Theo đơn vị';
    const methodByDocId = new Map();

    const methodForDoc = (docId) => methodByDocId.get(docId) || DEFAULT_SHARED_METHOD;

    const refreshMethodCheckmarks = (docId) => {
        const selected = methodForDoc(docId);
        document.querySelectorAll(`[data-doc-method-option="${docId}"]`).forEach((option) => {
            const active = (option.getAttribute('data-method-value') || '') === selected;
            option.classList.toggle('is-selected', active);
            option.setAttribute('aria-checked', active ? 'true' : 'false');
        });
    };

    document.querySelectorAll('.doc-name-row[data-doc-row]').forEach((row) => {
        const docId = row.getAttribute('data-doc-row') || '';
        if (!docId) return;
        methodByDocId.set(docId, DEFAULT_SHARED_METHOD);
        refreshMethodCheckmarks(docId);
    });

    document.querySelectorAll('[data-doc-more]').forEach((btn) => {
        btn.addEventListener('click', (e) => {
            e.stopPropagation();
            const docId = btn.getAttribute('data-doc-more');
            const bar = document.querySelector(`[data-doc-bar="${docId}"]`);
            if (!bar) return;
            const wasHidden = bar.hidden;
            closeAllDocMenus();
            closeAllMethodMenus();
            if (wasHidden) {
                bar.hidden = false;
            }
        });
    });

    document.querySelectorAll('[data-doc-method-toggle]').forEach((btn) => {
        btn.addEventListener('click', (e) => {
            e.stopPropagation();
            const docId = btn.getAttribute('data-doc-method-toggle');
            const menu = document.querySelector(`[data-doc-method-menu="${docId}"]`);
            if (!menu) return;
            const wasHidden = menu.hidden;
            closeAllDocMenus();
            closeAllMethodMenus();
            if (wasHidden) {
                if (docId) refreshMethodCheckmarks(docId);
                menu.hidden = false;
            }
        });
    });

    document.querySelectorAll('[data-doc-method-option]').forEach((item) => {
        item.addEventListener('click', (e) => {
            e.stopPropagation();
            const docId = item.getAttribute('data-doc-method-option');
            const method = item.getAttribute('data-method-value') || '';
            if (!docId) return;
            methodByDocId.set(docId, method || DEFAULT_SHARED_METHOD);
            refreshMethodCheckmarks(docId);
            closeAllMethodMenus();
        });
    });

    const submitDocAction = async (btn) => {
        if (!clientUi.requireOnline()) {
            return;
        }
        const action = btn.getAttribute('data-doc-action') || '';
        const docId = btn.getAttribute('data-act-id') || '';
        const card = btn.closest('.document-list-card');
        const unitId = card?.getAttribute('data-doc-unit') || '';
        const csrf = card?.getAttribute('data-doc-csrf') || '';
        if (!action || !docId || !unitId || !csrf) {
            return;
        }

        let value = '';
        if (action === 'rename') {
            const nextName = window.prompt('Nhập tên mới của tài liệu:');
            if (!nextName) return;
            value = nextName.trim();
            if (!value) return;
        }
        if (action === 'delete') {
            const confirmDelete = window.confirm('Xóa tài liệu này?');
            if (!confirmDelete) return;
        }

        const body = new URLSearchParams();
        body.set('csrf', csrf);
        body.set('action', action);
        body.set('value', value);

        try {
            const response = await fetch(`/units/${encodeURIComponent(unitId)}/documents/${encodeURIComponent(docId)}/menu-action`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                credentials: 'same-origin',
                body: body.toString(),
            });
            if (!response.ok) {
                window.alert('Không xử lý được thao tác tài liệu.');
                return;
            }
            window.location.reload();
        } catch (_) {
            window.alert('Kết nối thất bại khi xử lý tài liệu.');
        }
    };

    document.querySelectorAll('[data-doc-action]').forEach((btn) => {
        btn.addEventListener('click', async (e) => {
            e.stopPropagation();
            closeAllDocMenus();
            closeAllMethodMenus();
            await submitDocAction(btn);
        });
    });

    document.querySelectorAll('[data-doc-sync="true"]').forEach((btn) => {
        btn.addEventListener('click', async (e) => {
            e.stopPropagation();
            if (!clientUi.requireOnline()) {
                return;
            }
            const card = btn.closest('.document-list-card');
            const unitId = card?.getAttribute('data-doc-unit') || '';
            const csrf = card?.getAttribute('data-doc-csrf') || '';
            if (!unitId || !csrf) return;

            const methods = {};
            Array.from(card.querySelectorAll('.doc-name-row[data-doc-row]')).forEach((row, index) => {
                const docId = row.getAttribute('data-doc-row') || '';
                methods[String(index + 1)] = methodForDoc(docId);
            });

            const body = new URLSearchParams();
            body.set('csrf', csrf);
            body.set('methods_json', JSON.stringify(methods));

            btn.disabled = true;
            try {
                const response = await fetch(`/units/${encodeURIComponent(unitId)}/documents/sync-shared`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    credentials: 'same-origin',
                    body: body.toString(),
                });
                if (!response.ok) {
                    window.alert('Đồng bộ tài liệu thất bại.');
                    btn.disabled = false;
                    return;
                }
                window.location.reload();
            } catch (_) {
                window.alert('Kết nối thất bại khi đồng bộ tài liệu.');
                btn.disabled = false;
            }
        });
    });

    document.addEventListener('click', () => {
        closeAllDocMenus();
        closeAllMethodMenus();
    });


        const docAddShells = Array.from(document.querySelectorAll('[data-doc-add-shell="true"]'));
    docAddShells.forEach((shell) => {
        const toggle = shell.querySelector('[data-doc-add-toggle="true"]');
        const panel = shell.querySelector('[data-doc-add-panel="true"]');
        const searchInput = shell.querySelector('[data-doc-add-search="true"]');
        const resultsContainer = shell.querySelector('[data-doc-add-results="true"]');
        if (!toggle || !panel) return;

        const allItems = () => Array.from(resultsContainer?.querySelectorAll('[data-doc-add-item]') || []);
        const filterItems = (query) => {
            const q = (query || '').trim().toLowerCase();
            allItems().forEach((item) => {
                const name = (item.getAttribute('data-doc-add-name') || '').toLowerCase();
                item.style.display = (!q || name.includes(q)) ? '' : 'none';
            });
        };

        toggle.addEventListener('click', (e) => {
            e.stopPropagation();
            const wasHidden = panel.hidden;
            panel.hidden = true;
            if (wasHidden) {
                // Position the floating dropdown below-left of the + button
                const rect = toggle.getBoundingClientRect();
                panel.style.top = (rect.bottom + 6) + 'px';
                panel.style.left = Math.max(4, rect.left - 200 + rect.width) + 'px';
                panel.hidden = false;
                if (searchInput) { searchInput.value = ''; filterItems(''); searchInput.focus(); }
            }
        });

        searchInput?.addEventListener('input', () => filterItems(searchInput.value));

        allItems().forEach((item) => {
            item.addEventListener('click', () => {
                const docId = item.getAttribute('data-doc-add-id');
                if (docId && openDocument) {
                    openDocument(docId, true);
                }
                panel.hidden = true;
                if (searchInput) searchInput.value = '';
                filterItems('');
            });
        });

        document.addEventListener('click', (e) => {
            if (!shell.contains(e.target)) panel.hidden = true;
        });
    });
    // Mark top-3 items in each group as recently-changed
    docAddShells.forEach((shell) => {
        let currentGroup = null;
        let groupCount = 0;
        const children = Array.from(shell.querySelector('[data-doc-add-results="true"]')?.children || []);
        children.forEach((child) => {
            if (child.classList.contains('xl-doc-add-group-label')) {
                currentGroup = child;
                groupCount = 0;
            } else if (child.hasAttribute('data-doc-add-item')) {
                groupCount += 1;
                if (groupCount <= 3) child.classList.add('is-recent');
            }
        });
    });
})();
        "#
}

fn sync_client_script() -> &'static str {
    r#"
(() => {
    if (window.WebsiteBuuSync) {
        return;
    }

    const encoder = new TextEncoder();
    const decoder = new TextDecoder();
    const CACHE_PREFIX = 'website_buu.sync.cache.';
    const CACHE_KEY_PREFIX = 'website_buu.sync.cache-key.';
    const TRANSPORT_KEY_PREFIX = 'website_buu.sync.transport.';
    const ACTION_QUEUE_PREFIX = 'website_buu.sync.action-queue.';
    const POLL_MS = 15000;
    let swRegistrationPromise = null;
    let activeIdentity = null;
    let queueFlushPromise = null;

    const bytesToBase64 = (bytes) => {
        let binary = '';
        bytes.forEach((value) => {
            binary += String.fromCharCode(value);
        });
        return btoa(binary);
    };

    const base64ToBytes = (value) => Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
    const transportKeyStorage = (username) => `${TRANSPORT_KEY_PREFIX}${username.toLowerCase()}`;
    const cacheKeyStorage = (username) => `${CACHE_KEY_PREFIX}${username.toLowerCase()}`;
    const cacheStorage = (username) => `${CACHE_PREFIX}${username.toLowerCase()}`;
    const actionQueueStorage = (username) => `${ACTION_QUEUE_PREFIX}${username.toLowerCase()}`;
    let noticeTimer = null;
    const actionPolicy = Object.freeze({
        'password-change': { channel: 'server', offline: 'queue' },
        'network-settings': { channel: 'server', offline: 'queue' },
        'profile-document-save': { channel: 'server', offline: 'queue' },
        'chat-message': { channel: 'server', offline: 'queue' },
        'tree-user-credentials': { channel: 'server', offline: 'queue' },
        'shared-document-sync': { channel: 'server', offline: 'queue' },
        'document-menu-action': { channel: 'server', offline: 'queue' },
        'member-export': { channel: 'server', offline: 'online-only' },
    });

    const ensureOfflineToast = () => {
        let toast = document.querySelector('[data-offline-toast="true"]');
        if (toast) {
            return toast;
        }
        toast = document.createElement('div');
        toast.className = 'offline-toast';
        toast.hidden = true;
        toast.setAttribute('data-offline-toast', 'true');
        document.body.appendChild(toast);
        return toast;
    };

    const hideNotice = () => {
        const toast = document.querySelector('[data-offline-toast="true"]');
        if (!toast) return;
        toast.classList.remove('is-visible', 'is-success', 'is-error');
        window.setTimeout(() => {
            if (!toast.classList.contains('is-visible')) {
                toast.hidden = true;
            }
        }, 180);
    };

    const showNotice = (message = 'Bạn đang Offline!', tone = 'offline') => {
        if (!document.body) return;
        const toast = ensureOfflineToast();
        if (noticeTimer) {
            window.clearTimeout(noticeTimer);
        }
        toast.hidden = false;
        toast.textContent = message;
        toast.classList.toggle('is-success', tone === 'success');
        toast.classList.toggle('is-error', tone === 'error');
        requestAnimationFrame(() => toast.classList.add('is-visible'));
        noticeTimer = window.setTimeout(() => {
            hideNotice();
        }, tone === 'offline' ? 2200 : 1800);
    };

    const isOffline = () => navigator.onLine === false;
    const requireOnline = (message = 'Bạn đang Offline!') => {
        if (!isOffline()) {
            return true;
        }
        showNotice(message, 'offline');
        return false;
    };

    const bindOnlineForms = () => {
        document.querySelectorAll('form[method="post"]').forEach((form) => {
            if (form.dataset.onlineGuardBound === 'true' || form.dataset.offlineBypass === 'true' || form.dataset.offlineMode === 'queue') {
                return;
            }
            form.dataset.onlineGuardBound = 'true';
            form.addEventListener('submit', (event) => {
                if (requireOnline()) {
                    return;
                }
                event.preventDefault();
            });
        });
    };

    window.addEventListener('offline', () => showNotice('Bạn đang Offline!', 'offline'));
    const emptyActionQueue = () => ({ version: 1, items: [] });

    const normalizeHeaders = (headers = {}) => Object.fromEntries(
        Object.entries(headers || {}).filter((entry) => entry[1] !== undefined && entry[1] !== null && entry[1] !== ''),
    );

    const loadEncryptedSlot = async (storageKey, keyBytes, fallbackValue) => {
        const encrypted = localStorage.getItem(storageKey);
        if (!encrypted) {
            return fallbackValue;
        }
        try {
            return await decryptJson(keyBytes, JSON.parse(encrypted));
        } catch (_) {
            localStorage.removeItem(storageKey);
            return fallbackValue;
        }
    };

    const saveEncryptedSlot = async (storageKey, keyBytes, payload) => {
        localStorage.setItem(storageKey, JSON.stringify(await encryptJson(keyBytes, payload)));
    };

    const currentIdentity = () => {
        if (activeIdentity?.username && activeIdentity?.cacheKeyB64 && activeIdentity?.transportKeyB64) {
            return activeIdentity;
        }
        const username = document.body?.getAttribute('data-sync-username');
        if (!username) {
            return null;
        }
        const transportKeyB64 = sessionStorage.getItem(transportKeyStorage(username));
        const cacheKeyB64 = sessionStorage.getItem(cacheKeyStorage(username));
        if (!transportKeyB64 || !cacheKeyB64) {
            return null;
        }
        activeIdentity = { username, transportKeyB64, cacheKeyB64 };
        return activeIdentity;
    };

    const loadActionQueue = async (identity) => {
        if (!identity?.username || !identity?.cacheKeyB64) {
            return emptyActionQueue();
        }
        return loadEncryptedSlot(actionQueueStorage(identity.username), base64ToBytes(identity.cacheKeyB64), emptyActionQueue());
    };

    const saveActionQueue = async (identity, queue) => {
        if (!identity?.username || !identity?.cacheKeyB64) {
            return;
        }
        await saveEncryptedSlot(actionQueueStorage(identity.username), base64ToBytes(identity.cacheKeyB64), queue);
    };

    const buildQueuedAction = (type, request, meta = {}) => ({
        id: `queued-${Date.now()}-${Math.random().toString(16).slice(2)}`,
        type,
        created_at: new Date().toISOString(),
        attempts: 0,
        request: {
            url: request.url,
            method: request.method || 'POST',
            headers: normalizeHeaders(request.headers),
            body: request.body || '',
        },
        meta,
    });

    const enqueueAction = async (type, request, meta = {}) => {
        const identity = currentIdentity();
        if (!identity) {
            return { queued: false, missingIdentity: true };
        }
        const queue = await loadActionQueue(identity);
        queue.items.push(buildQueuedAction(type, request, meta));
        await saveActionQueue(identity, queue);
        return { queued: true };
    };

    const buildFormRequest = (form, options = {}) => {
        const params = new URLSearchParams(new FormData(form));
        return {
            url: form.getAttribute('action') || window.location.href,
            method: (form.getAttribute('method') || 'POST').toUpperCase(),
            headers: normalizeHeaders({
                'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
                Accept: options.accept || 'text/html,application/xhtml+xml',
            }),
            body: params.toString(),
        };
    };

    const parseResponsePayload = async (response, mode = 'json') => {
        if (mode === 'text') {
            return response.text().catch(() => '');
        }
        return response.json().catch(() => null);
    };

    const flushQueuedActions = async ({ silent = false } = {}) => {
        if (queueFlushPromise) {
            return queueFlushPromise;
        }
        const identity = currentIdentity();
        if (!identity || isOffline()) {
            return { processed: 0, remaining: 0 };
        }
        queueFlushPromise = (async () => {
            const queue = await loadActionQueue(identity);
            if (!Array.isArray(queue.items) || queue.items.length === 0) {
                return { processed: 0, remaining: 0 };
            }
            const remaining = [];
            let processed = 0;
            for (let index = 0; index < queue.items.length; index += 1) {
                const item = queue.items[index];
                try {
                    const response = await fetch(item.request.url, {
                        method: item.request.method || 'POST',
                        credentials: 'same-origin',
                        headers: normalizeHeaders(item.request.headers),
                        body: item.request.body || undefined,
                    });
                    if (response.ok) {
                        processed += 1;
                        continue;
                    }
                    if (response.status === 401 || response.status === 403) {
                        remaining.push(...queue.items.slice(index));
                        break;
                    }
                    remaining.push({ ...item, attempts: (item.attempts || 0) + 1, last_status: response.status });
                } catch (_) {
                    remaining.push({ ...item, attempts: (item.attempts || 0) + 1, last_error: 'network' });
                    remaining.push(...queue.items.slice(index + 1));
                    break;
                }
            }
            await saveActionQueue(identity, { version: 1, items: remaining });
            if (processed > 0 && !silent) {
                showNotice(`Đã đồng bộ ${processed} thay đổi đang chờ.`, 'success');
            }
            return { processed, remaining: remaining.length };
        })().finally(() => {
            queueFlushPromise = null;
        });
        return queueFlushPromise;
    };

    const submitServerAction = async ({ type, request, responseType = 'json', queueMessage = 'Đã lưu vào hàng đợi, sẽ gửi khi online.' }) => {
        const policy = actionPolicy[type] || { offline: 'online-only' };
        if (isOffline()) {
            if (policy.offline !== 'queue') {
                showNotice('Bạn đang Offline!', 'offline');
                return { ok: false, queued: false, offlineBlocked: true };
            }
            const queued = await enqueueAction(type, request, { responseType });
            if (queued.queued) {
                return { ok: true, queued: true };
            }
            showNotice('Bạn đang Offline!', 'offline');
            return { ok: false, queued: false, offlineBlocked: true };
        }

        try {
            const response = await fetch(request.url, {
                method: request.method || 'POST',
                credentials: 'same-origin',
                headers: normalizeHeaders(request.headers),
                body: request.body || undefined,
            });
            const payload = await parseResponsePayload(response.clone(), responseType);
            if (response.ok) {
                return { ok: true, queued: false, response, payload };
            }
            return { ok: false, queued: false, response, payload };
        } catch (_) {
            if (policy.offline !== 'queue') {
                return { ok: false, queued: false, offlineBlocked: true };
            }
            const queued = await enqueueAction(type, request, { responseType });
            if (queued.queued) {
                return { ok: true, queued: true };
            }
            return { ok: false, queued: false, offlineBlocked: true };
        }
    };

    window.addEventListener('online', () => {
        hideNotice();
        flushQueuedActions({ silent: false }).catch(() => {});
    });
    window.WebsiteBuuClientUi = { isOffline, requireOnline, showNotice, bindOnlineForms };
    bindOnlineForms();

    const ensureServiceWorker = () => {
        if (!('serviceWorker' in navigator)) {
            return Promise.resolve(null);
        }
        if (!swRegistrationPromise) {
            swRegistrationPromise = navigator.serviceWorker.register('/service-worker.js?v=3', { scope: '/' }).catch(() => null);
        }
        return swRegistrationPromise;
    };

    const warmServiceWorker = async (extraUrls = []) => {
        const registration = await ensureServiceWorker();
        if (!registration) return;
        const worker = registration.active || registration.waiting || registration.installing;
        if (!worker) return;
        const urls = Array.from(new Set(['/', window.location.pathname + window.location.search, ...extraUrls].filter(Boolean)));
        worker.postMessage({ type: 'warm-cache', urls });
    };

    const importAesKey = async (keyBytes) => crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt', 'decrypt']);

    const deriveCacheKey = async (username, password) => {
        const material = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
        const salt = encoder.encode(`website-buu-cache:${location.origin}:${username.toLowerCase()}`);
        const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 150000 }, material, 256);
        return new Uint8Array(bits);
    };

    const encryptJson = async (keyBytes, payload) => {
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const key = await importAesKey(keyBytes);
        const plaintext = encoder.encode(JSON.stringify(payload));
        const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext));
        return { iv_b64: bytesToBase64(iv), ciphertext_b64: bytesToBase64(ciphertext) };
    };

    const decryptJson = async (keyBytes, payload) => {
        const key = await importAesKey(keyBytes);
        const plaintext = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: base64ToBytes(payload.iv_b64) },
            key,
            base64ToBytes(payload.ciphertext_b64),
        );
        return JSON.parse(decoder.decode(plaintext));
    };

    const mergeCollection = (current = [], incoming = []) => {
        const merged = new Map(current.map((item) => [item.id, item]));
        incoming.forEach((item) => merged.set(item.id, item));
        return Array.from(merged.values());
    };

    const mergeSnapshot = (current, incoming) => ({
        organizations: mergeCollection(current.organizations, incoming.organizations),
        members: mergeCollection(current.members, incoming.members),
        activities: mergeCollection(current.activities, incoming.activities),
        documents: mergeCollection(current.documents, incoming.documents),
    });

    const emptyCache = () => ({
        generated_at: '',
        latest_update_at: '',
        snapshot: {
            organizations: [],
            members: [],
            activities: [],
            documents: [],
        },
    });

    const applyDocumentsToDom = (documents = []) => {
        const byId = new Map(documents.map((item) => [item.id, item]));
        document.querySelectorAll('[data-doc-id]').forEach((element) => {
            const doc = byId.get(element.getAttribute('data-doc-id') || '');
            if (!doc) {
                return;
            }
            if (element.tagName === 'TEXTAREA') {
                if (document.activeElement === element) {
                    return;
                }
                if (element.value !== doc.preview_text) {
                    element.value = doc.preview_text;
                    element.dispatchEvent(new Event('input', { bubbles: true }));
                }
            } else if (element.textContent !== doc.preview_text) {
                element.textContent = doc.preview_text;
            }
            element.setAttribute('data-doc-updated-at', doc.updated_at || '');
        });
        window.WebsiteBuuProfileDocsSync?.applyDocuments?.(documents);
    };

    const prepareLoginForm = (form) => {
        if (form.dataset.syncPrepared === 'true') {
            return;
        }
        form.dataset.syncPrepared = 'true';
        form.addEventListener('submit', (event) => {
            const usernameInput = form.querySelector('input[name="username"]');
            const passwordInput = form.querySelector('input[name="password"]');
            const username = (usernameInput?.value || '').trim();
            const password = passwordInput?.value || '';
            if (!username || !password) {
                return;
            }
            event.preventDefault();
            Promise.resolve()
                .then(async () => {
                    const transportKey = crypto.getRandomValues(new Uint8Array(32));
                    const cacheKey = await deriveCacheKey(username, password);
                    sessionStorage.setItem(transportKeyStorage(username), bytesToBase64(transportKey));
                    sessionStorage.setItem(cacheKeyStorage(username), bytesToBase64(cacheKey));
                    activeIdentity = {
                        username,
                        transportKeyB64: bytesToBase64(transportKey),
                        cacheKeyB64: bytesToBase64(cacheKey),
                    };
                })
                .finally(() => form.submit());
        });
    };

    let syncInFlight = null;
    let pollTimer = null;

    const boot = () => {
        bindOnlineForms();
        ensureServiceWorker().then(() => warmServiceWorker(['/documents/manage'])).catch(() => {});
        const username = document.body?.getAttribute('data-sync-username');
        if (!username) {
            return;
        }
        const transportKeyB64 = sessionStorage.getItem(transportKeyStorage(username));
        const cacheKeyB64 = sessionStorage.getItem(cacheKeyStorage(username));
        if (!transportKeyB64 || !cacheKeyB64) {
            return;
        }
        activeIdentity = { username, transportKeyB64, cacheKeyB64 };

        const runSync = async () => {
            const cacheKey = base64ToBytes(cacheKeyB64);
            const transportKey = base64ToBytes(transportKeyB64);
            const cacheSlot = cacheStorage(username);
            let cache = emptyCache();
            const encryptedCache = localStorage.getItem(cacheSlot);
            if (encryptedCache) {
                try {
                    cache = await decryptJson(cacheKey, JSON.parse(encryptedCache));
                } catch (_) {
                    localStorage.removeItem(cacheSlot);
                    cache = emptyCache();
                }
            }

            const syncUrl = new URL('/sync/bootstrap', window.location.origin);
            if (cache.latest_update_at) {
                syncUrl.searchParams.set('since', cache.latest_update_at);
            }

            try {
                const response = await fetch(syncUrl.toString(), {
                    credentials: 'same-origin',
                    headers: {
                        'Accept': 'application/json',
                        'X-Browser-Sync-Key': transportKeyB64,
                        'X-Requested-With': 'XMLHttpRequest',
                    },
                });
                if (!response.ok) {
                    return;
                }

                const envelope = await response.json();
                const payload = await decryptJson(transportKey, {
                    iv_b64: envelope.nonce_b64,
                    ciphertext_b64: envelope.ciphertext_b64,
                });
                const merged = payload.full_sync
                    ? payload
                    : {
                        generated_at: payload.generated_at,
                        latest_update_at: payload.latest_update_at || cache.latest_update_at,
                        snapshot: mergeSnapshot(cache.snapshot || emptyCache().snapshot, payload.snapshot || emptyCache().snapshot),
                    };

                if (!payload.full_sync && !merged.latest_update_at) {
                    merged.latest_update_at = cache.latest_update_at || '';
                }

                localStorage.setItem(cacheSlot, JSON.stringify(await encryptJson(cacheKey, merged)));
                applyDocumentsToDom(merged.snapshot.documents || []);
                window.dispatchEvent(new CustomEvent('website-buu-sync-updated', { detail: merged }));
                flushQueuedActions({ silent: true }).catch(() => {});
            } catch (_) {
                if (isOffline()) {
                    return;
                }
            }
        };

        if (!syncInFlight) {
            syncInFlight = runSync().finally(() => {
                syncInFlight = null;
            });
        }
        if (!pollTimer) {
            pollTimer = window.setInterval(() => {
                if (!syncInFlight) {
                    syncInFlight = runSync().finally(() => {
                        syncInFlight = null;
                    });
                }
            }, POLL_MS);
        }
    };

    window.WebsiteBuuSync = { boot, prepareLoginForm, actionPolicy, currentIdentity, buildFormRequest, flushQueuedActions, submitServerAction };
    window.addEventListener('focus', () => boot());
    document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'visible') {
            boot();
        }
    });
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => boot(), { once: true });
    } else {
        window.setTimeout(() => boot(), 0);
    }
})();
    "#
}

fn service_worker_script() -> &'static str {
    r#"
const SHELL_CACHE = 'website-buu-shell-v3';
const RUNTIME_CACHE = 'website-buu-runtime-v3';

const sameOrigin = (url) => new URL(url, self.location.origin).origin === self.location.origin;

const isStaticAsset = (url) => {
    const p = url.pathname;
    return p.startsWith('/workers/') || p.endsWith('.js') || p.endsWith('.css') || p.endsWith('.woff2') || p.endsWith('.woff') || p.endsWith('.png') || p.endsWith('.svg');
};

const cacheResponse = async (cacheName, request, response) => {
    if (!response || !response.ok || (response.type !== 'basic' && response.type !== 'default')) {
        return response;
    }
    const cache = await caches.open(cacheName);
    await cache.put(request, response.clone());
    return response;
};

const fetchAndCache = async (cacheName, request) => {
    const response = await fetch(request);
    return cacheResponse(cacheName, request, response);
};

self.addEventListener('install', (event) => {
    event.waitUntil((async () => {
        const cache = await caches.open(SHELL_CACHE);
        await self.skipWaiting();
    })());
});

self.addEventListener('activate', (event) => {
    event.waitUntil((async () => {
        const names = await caches.keys();
        await Promise.all(names.filter((name) => ![SHELL_CACHE, RUNTIME_CACHE].includes(name)).map((name) => caches.delete(name)));
        await self.clients.claim();
    })());
});

self.addEventListener('message', (event) => {
    const payload = event.data || {};
    if (payload.type !== 'warm-cache' || !Array.isArray(payload.urls)) {
        return;
    }
    event.waitUntil((async () => {
        const cache = await caches.open(SHELL_CACHE);
        for (const rawUrl of payload.urls) {
            if (!rawUrl) continue;
            const url = new URL(rawUrl, self.location.origin);
            if (!sameOrigin(url.href)) continue;
            if (!isStaticAsset(url)) continue;
            try {
                const response = await fetch(new Request(url.href, { credentials: 'same-origin' }));
                await cacheResponse(SHELL_CACHE, url.href, response);
            } catch (_) {}
        }
    })());
});

self.addEventListener('fetch', (event) => {
    const request = event.request;
    if (request.method !== 'GET') {
        return;
    }
    const url = new URL(request.url);
    if (!sameOrigin(url.href)) {
        return;
    }
    if (url.pathname === '/sync/bootstrap' || url.pathname === '/health') {
        return;
    }

    // Navigation requests contain user-specific HTML — never serve from cache.
    // Always fetch from network so a freshly logged-in user always gets their own page.
    if (request.mode === 'navigate') {
        return;
    }

    if (request.destination === 'script' || request.destination === 'worker') {
        event.respondWith((async () => {
            const cache = await caches.open(SHELL_CACHE);
            const cached = await cache.match(request);
            const networkPromise = fetchAndCache(SHELL_CACHE, request).catch(() => null);
            if (cached) {
                event.waitUntil(networkPromise);
                return cached;
            }
            return (await networkPromise) || Response.error();
        })());
        return;
    }

    event.respondWith((async () => {
        const cache = await caches.open(RUNTIME_CACHE);
        const cached = await cache.match(request);
        const networkPromise = fetchAndCache(RUNTIME_CACHE, request).catch(() => null);
        if (cached) {
            event.waitUntil(networkPromise);
            return cached;
        }
        return (await networkPromise) || Response.error();
    })());
});
    "#
}

fn login_script() -> &'static str {
    r#"
(() => {
    const loginForm = document.querySelector('form[action="/login"]');
    if (loginForm && window.WebsiteBuuSync?.prepareLoginForm) {
        window.WebsiteBuuSync.prepareLoginForm(loginForm);
    }
    const loginCard = document.querySelector('.login-card');
    if (loginCard?.classList.contains('login-error-flash')) {
        window.setTimeout(() => {
            loginCard.classList.remove('login-error-flash');
        }, 500);
    }
    const submitButton = document.querySelector('[data-login-submit="true"]');
    if (!submitButton) return;

    const waitMessage = document.querySelector('[data-login-wait-message="true"]');
    const unlockAt = Number.parseInt(submitButton.getAttribute('data-login-unlock-at') || '', 10);
    if (!Number.isFinite(unlockAt)) {
        submitButton.disabled = false;
        return;
    }

    if (unlockAt <= Date.now()) {
        submitButton.disabled = false;
        if (waitMessage) {
            waitMessage.hidden = true;
        }
        if (loginCard) {
            loginCard.classList.remove('login-error-flash');
        }
        return;
    }

    const renderCountdown = () => {
        const remainingMs = unlockAt - Date.now();
        if (remainingMs <= 0) {
            submitButton.disabled = false;
            submitButton.removeAttribute('data-login-unlock-at');
            if (waitMessage) {
                waitMessage.hidden = true;
                waitMessage.textContent = '';
            }
            if (loginCard) {
                loginCard.classList.remove('login-error-flash');
            }
            window.clearInterval(timerId);
            return;
        }

        const totalSeconds = Math.ceil(remainingMs / 1000);
        const minutes = Math.floor(totalSeconds / 60);
        const seconds = totalSeconds % 60;
        if (waitMessage) {
            waitMessage.hidden = false;
            waitMessage.textContent = `${minutes}:${String(seconds).padStart(2, '0')}`;
        }
    };

    submitButton.disabled = true;
    renderCountdown();
    const timerId = window.setInterval(renderCountdown, 1000);
})();
    "#
}

fn edge_points(
    from_x: f32,
    from_y: f32,
    from_radius: f32,
    to_x: f32,
    to_y: f32,
    to_radius: f32,
) -> (f32, f32, f32, f32) {
    let dx = to_x - from_x;
    let dy = to_y - from_y;
    let distance = (dx * dx + dy * dy).sqrt().max(1.0);
    let unit_x = dx / distance;
    let unit_y = dy / distance;
    (
        from_x + unit_x * from_radius,
        from_y + unit_y * from_radius,
        to_x - unit_x * to_radius,
        to_y - unit_y * to_radius,
    )
}

#[derive(Deserialize)]
struct NetworkSettingsForm {
    csrf: String,
    mode: String,
    #[serde(default)]
    ip_whitelist: String,
}

#[derive(Deserialize)]
struct PasswordSettingsForm {
    csrf: String,
    current_password: String,
    new_password: String,
    confirm_password: String,
}

#[derive(Serialize)]
struct NetworkSettingsResponse {
    mode: String,
    is_lan: bool,
    ip_whitelist: Vec<String>,
    message: String,
}

#[derive(Serialize)]
struct PasswordSettingsResponse {
    ok: bool,
    message: String,
}

#[cfg(test)]
type EncryptedSyncEnvelope = crate::hybird::HybirdEnvelope;
