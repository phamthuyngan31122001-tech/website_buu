use std::collections::{HashMap, HashSet};

use chrono::Utc;
use rand::{Rng, distributions::Alphanumeric, thread_rng};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default)]
pub struct AppData {
    pub organizations: Vec<Organization>,
    pub users: Vec<User>,
    pub members: Vec<Member>,
    pub activities: Vec<Activity>,
    pub documents: Vec<Document>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Organization {
    pub id: String,
    pub parent_id: Option<String>,
    pub name: String,
    pub tier: u32,
    pub category: String,
    pub active: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum UserRole {
    RootAdmin,
    OrgManager,
}

impl UserRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RootAdmin => "root_admin",
            Self::OrgManager => "org_manager",
        }
    }

    pub fn from_value(value: &str) -> Self {
        match value {
            "root_admin" => Self::RootAdmin,
            _ => Self::OrgManager,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct User {
    pub id: String,
    pub username: String,
    pub password_hash: String,
    pub role: UserRole,
    pub org_id: Option<String>,
    pub tree_key_enabled: bool,
    pub active: bool,
    pub created_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Member {
    pub id: String,
    pub org_id: String,
    pub full_name: String,
    pub title: String,
    pub year: i32,
    pub active: bool,
    pub notes: String,
    pub birth_date: String,
    pub address: String,
    pub phone: String,
    pub joined_at: String,
    pub updated_at: String,
}

impl Member {
    pub fn is_key_member(&self) -> bool {
        matches!(self.title.as_str(), "Bí thư" | "Phó bí thư" | "Chủ tịch")
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ActivityStatus {
    Completed,
    Ongoing,
    Planned,
}

impl ActivityStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Ongoing => "ongoing",
            Self::Planned => "planned",
        }
    }

    pub fn from_value(value: &str) -> Self {
        match value {
            "completed" => Self::Completed,
            "ongoing" => Self::Ongoing,
            _ => Self::Planned,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Activity {
    pub id: String,
    pub org_id: String,
    pub title: String,
    pub year: i32,
    pub status: ActivityStatus,
    pub summary: String,
    pub reviewed: bool,
    pub updated_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Document {
    pub id: String,
    pub org_id: String,
    pub title: String,
    pub file_name: String,
    pub mime_type: String,
    pub preview_text: String,
    pub year: i32,
    pub encrypted_path: String,
    pub kem_ciphertext_b64: String,
    pub nonce_b64: String,
    pub uploaded_at: String,
    pub updated_at: String,
}

pub fn now_string() -> String {
    Utc::now().to_rfc3339()
}

pub fn new_id(prefix: &str) -> String {
    let random_part: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(8)
        .map(char::from)
        .collect();
    format!(
        "{}-{}-{}",
        prefix,
        Utc::now().timestamp_millis(),
        random_part
    )
}

pub fn descendant_ids(organizations: &[Organization], root_id: &str) -> HashSet<String> {
    let mut children_by_parent: HashMap<&str, Vec<&str>> = HashMap::new();
    for org in organizations {
        if let Some(parent_id) = org.parent_id.as_deref() {
            children_by_parent
                .entry(parent_id)
                .or_default()
                .push(org.id.as_str());
        }
    }

    let mut visible = HashSet::from([root_id.to_owned()]);
    let mut stack = vec![root_id];
    while let Some(current_id) = stack.pop() {
        let Some(children) = children_by_parent.get(current_id) else {
            continue;
        };
        for child_id in children {
            if visible.insert((*child_id).to_owned()) {
                stack.push(child_id);
            }
        }
    }

    visible
}

pub fn ancestor_ids(organizations: &[Organization], node_id: &str) -> HashSet<String> {
    let parent_by_id: HashMap<&str, &str> = organizations
        .iter()
        .filter_map(|org| {
            org.parent_id
                .as_deref()
                .map(|parent_id| (org.id.as_str(), parent_id))
        })
        .collect();

    let mut ancestors = HashSet::new();
    let mut current = parent_by_id.get(node_id).copied();

    while let Some(parent_id) = current {
        if !ancestors.insert(parent_id.to_owned()) {
            break;
        }
        current = parent_by_id.get(parent_id).copied();
    }

    ancestors
}
