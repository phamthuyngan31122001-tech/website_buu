use crate::models::{Document, Organization};

const LEGACY_SEED_FILE_NAMES: &[&str] = &[
    "sample-doc.txt",
    "Sổ tổng hợp nhân sự.xlsx",
    "Lịch điều hành quý.xlsx",
    "Theo dõi chỉ tiêu.xlsx",
    "Phân công xử lý hồ sơ.xlsx",
    "Bảng tiến độ đào tạo.xlsx",
    "Theo dõi ngân sách chung.xlsx",
];

const LEGACY_SEED_TITLES: &[&str] = &[
    "Tai lieu dong nhat F 1",
    "Tai lieu dong nhat F 2",
    "Tai lieu dong nhat F 3",
    "Tai lieu dong nhat F 4",
    "Tai lieu dong nhat F 5",
    "Tai lieu dong nhat F 6",
];

pub fn default_root_admin_credentials() -> (&'static str, &'static str) {
    ("admin", "admin")
}

pub fn direct_children(organizations: &[Organization], parent_id: &str) -> Vec<Organization> {
    organizations
        .iter()
        .filter(|org| org.parent_id.as_deref() == Some(parent_id))
        .cloned()
        .collect()
}

pub fn org_sort_key(name: &str) -> (String, u32) {
    let prefix: String = name
        .chars()
        .take_while(|ch| ch.is_ascii_alphabetic())
        .collect();
    let number = name
        .chars()
        .skip_while(|ch| ch.is_ascii_alphabetic())
        .collect::<String>()
        .parse::<u32>()
        .unwrap_or(0);
    (prefix, number)
}

fn default_org_user_code(organizations: &[Organization], org_id: &str) -> Option<String> {
    let current = organizations.iter().find(|org| org.id == org_id)?;
    if current.tier == 0 {
        return Some("0".to_owned());
    }

    let mut segments = Vec::new();
    let mut cursor = current;
    loop {
        if cursor.tier == 0 {
            break;
        }
        let parent_id = cursor.parent_id.as_deref()?;
        let mut siblings = direct_children(organizations, parent_id);
        siblings.sort_by(|left, right| org_sort_key(&left.name).cmp(&org_sort_key(&right.name)));
        let index = siblings
            .iter()
            .position(|item| item.id == cursor.id)
            .map(|value| value + 1)
            .unwrap_or(1);
        segments.push(index.to_string());
        let Some(parent) = organizations.iter().find(|org| org.id == parent_id) else {
            break;
        };
        cursor = parent;
    }

    segments.reverse();
    if segments.is_empty() {
        Some(current.name.to_lowercase())
    } else {
        Some(segments.join(""))
    }
}

pub fn default_org_user_credentials(
    organizations: &[Organization],
    org_id: &str,
) -> Option<(String, String)> {
    let code = default_org_user_code(organizations, org_id)?;
    Some((code.clone(), code))
}

pub fn can_upload_documents(organizations: &[Organization], org_id: &str) -> bool {
    !organizations
        .iter()
        .any(|org| org.parent_id.as_deref() == Some(org_id))
}

pub fn is_shared_document(document: &Document) -> bool {
    document.file_name.starts_with("tai-lieu-chung-")
        || document.title.starts_with("Tài liệu chung ")
        || document.title.starts_with("Tài liệu đồng bộ")
}

pub fn is_legacy_demo_document(document: &Document) -> bool {
    LEGACY_SEED_FILE_NAMES
        .iter()
        .any(|name| *name == document.file_name)
        || LEGACY_SEED_TITLES
            .iter()
            .any(|title| *title == document.title)
}
