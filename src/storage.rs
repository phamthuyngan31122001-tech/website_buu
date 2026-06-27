use std::{
    fs,
    io::Cursor,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, anyhow};
use arrow_array::{Array, BooleanArray, Int32Array, RecordBatch, StringArray, UInt32Array};
use arrow_ipc::{reader::FileReader, writer::FileWriter};
use arrow_schema::{DataType, Field, Schema};
use chrono::{DateTime, Duration, Utc};

use crate::{
    crypto::{MasterKey, decrypt_blob_with_context, encrypt_blob_with_context},
    models::{
        Activity, ActivityStatus, AppData, Document, Member,
        Organization, User, UserRole,
    },
};

pub struct Storage {
    base_dir: PathBuf,
    cache_dir: PathBuf,
    docs_dir: PathBuf,
    master_key: MasterKey,
}

impl Storage {
    pub fn new(base_dir: impl AsRef<Path>, master_key: MasterKey) -> anyhow::Result<Self> {
        let base_dir = base_dir.as_ref().to_path_buf();
        let cache_dir = base_dir.join("cache");
        let docs_dir = base_dir.join("documents");
        fs::create_dir_all(&docs_dir).context("failed to create data directories")?;
        fs::create_dir_all(&cache_dir).context("failed to create cache directories")?;
        Ok(Self {
            base_dir,
            cache_dir,
            docs_dir,
            master_key,
        })
    }

    pub fn docs_dir(&self) -> &Path {
        &self.docs_dir
    }

    pub fn load(&self) -> anyhow::Result<AppData> {
        if self.snapshot_exists(&self.cache_dir) {
            let data = self.load_from_dir(&self.cache_dir)?;
            if self.cache_is_due()? {
                self.write_snapshot(&self.base_dir, &data)?;
                self.clear_cache()?;
            }
            return Ok(data);
        }
        self.load_from_dir(&self.base_dir)
    }

    pub fn save(&self, data: &AppData) -> anyhow::Result<()> {
        if self.cache_is_due()? {
            self.flush_cache_to_main(data)?;
            return Ok(());
        }

        self.ensure_cache_window()?;
        self.write_snapshot(&self.cache_dir, data)?;
        Ok(())
    }

    pub fn cache_due(&self) -> anyhow::Result<bool> {
        self.cache_is_due()
    }

    pub fn flush_cache_to_main(&self, data: &AppData) -> anyhow::Result<()> {
        self.write_snapshot(&self.base_dir, data)?;
        self.clear_cache()?;
        Ok(())
    }

    fn load_from_dir(&self, dir: &Path) -> anyhow::Result<AppData> {
        Ok(AppData {
            organizations: self.read_table_from(dir, "organizations.feather.enc", bytes_to_orgs)?,
            users: self.read_table_from(dir, "users.feather.enc", bytes_to_users)?,
            members: self.read_table_from(dir, "members.feather.enc", bytes_to_members)?,
            activities: self.read_table_from(dir, "activities.feather.enc", bytes_to_activities)?,
            documents: self.read_table_from(dir, "documents.feather.enc", bytes_to_documents)?,
        })
    }

    fn write_snapshot(&self, dir: &Path, data: &AppData) -> anyhow::Result<()> {
        self.write_table_to(
            dir,
            "organizations.feather.enc",
            &orgs_to_bytes(&data.organizations)?,
        )?;
        self.write_table_to(dir, "users.feather.enc", &users_to_bytes(&data.users)?)?;
        self.write_table_to(
            dir,
            "members.feather.enc",
            &members_to_bytes(&data.members)?,
        )?;
        self.write_table_to(
            dir,
            "activities.feather.enc",
            &activities_to_bytes(&data.activities)?,
        )?;
        self.write_table_to(
            dir,
            "documents.feather.enc",
            &documents_to_bytes(&data.documents)?,
        )?;
        Ok(())
    }

    fn snapshot_exists(&self, dir: &Path) -> bool {
        dir.join("organizations.feather.enc").exists()
    }

    fn cache_meta_path(&self) -> PathBuf {
        self.cache_dir.join("cache_started_at.txt")
    }

    fn ensure_cache_window(&self) -> anyhow::Result<()> {
        if !self.cache_meta_path().exists() {
            fs::write(self.cache_meta_path(), Utc::now().to_rfc3339())
                .context("failed to write cache metadata")?;
        }
        Ok(())
    }

    fn cache_is_due(&self) -> anyhow::Result<bool> {
        let meta_path = self.cache_meta_path();
        if !meta_path.exists() {
            return Ok(false);
        }
        let started_at = fs::read_to_string(meta_path).context("failed to read cache metadata")?;
        let started_at = DateTime::parse_from_rfc3339(started_at.trim())
            .context("failed to parse cache metadata")?
            .with_timezone(&Utc);
        Ok(Utc::now() - started_at >= Duration::hours(24))
    }

    fn clear_cache(&self) -> anyhow::Result<()> {
        for name in [
            "organizations.feather.enc",
            "users.feather.enc",
            "members.feather.enc",
            "activities.feather.enc",
            "documents.feather.enc",
            "cache_started_at.txt",
        ] {
            let path = self.cache_dir.join(name);
            if path.exists() {
                fs::remove_file(path).context("failed to remove cache artifact")?;
            }
        }
        Ok(())
    }

    fn read_table_from<T, F>(&self, dir: &Path, name: &str, parser: F) -> anyhow::Result<Vec<T>>
    where
        F: FnOnce(Vec<u8>) -> anyhow::Result<Vec<T>>,
    {
        let path = dir.join(name);
        if !path.exists() {
            return Ok(Vec::new());
        }
        let encrypted = fs::read(path).context("failed to read encrypted feather file")?;
        let bytes =
            decrypt_blob_with_context(&self.master_key, &self.blob_context(dir, name), &encrypted)?;
        parser(bytes)
    }

    fn write_table_to(&self, dir: &Path, name: &str, plaintext: &[u8]) -> anyhow::Result<()> {
        let encrypted =
            encrypt_blob_with_context(&self.master_key, &self.blob_context(dir, name), plaintext)?;
        fs::write(dir.join(name), encrypted).context("failed to write encrypted feather file")?;
        Ok(())
    }

    fn blob_context(&self, dir: &Path, name: &str) -> String {
        let scope = if dir == self.cache_dir.as_path() {
            "cache"
        } else {
            "main"
        };
        format!("{scope}::{name}")
    }
}

fn orgs_to_bytes(items: &[Organization]) -> anyhow::Result<Vec<u8>> {
    let schema = Arc::new(Schema::new(vec![
        Field::new("id", DataType::Utf8, false),
        Field::new("parent_id", DataType::Utf8, true),
        Field::new("name", DataType::Utf8, false),
        Field::new("tier", DataType::UInt32, false),
        Field::new("category", DataType::Utf8, false),
        Field::new("active", DataType::Boolean, false),
        Field::new("created_at", DataType::Utf8, false),
        Field::new("updated_at", DataType::Utf8, false),
    ]));

    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(StringArray::from(
                items.iter().map(|item| item.id.clone()).collect::<Vec<_>>(),
            )),
            Arc::new(StringArray::from(
                items
                    .iter()
                    .map(|item| item.parent_id.clone())
                    .collect::<Vec<_>>(),
            )),
            Arc::new(StringArray::from(
                items
                    .iter()
                    .map(|item| item.name.clone())
                    .collect::<Vec<_>>(),
            )),
            Arc::new(UInt32Array::from(
                items.iter().map(|item| item.tier).collect::<Vec<_>>(),
            )),
            Arc::new(StringArray::from(
                items
                    .iter()
                    .map(|item| item.category.clone())
                    .collect::<Vec<_>>(),
            )),
            Arc::new(BooleanArray::from(
                items.iter().map(|item| item.active).collect::<Vec<_>>(),
            )),
            Arc::new(StringArray::from(
                items
                    .iter()
                    .map(|item| item.created_at.clone())
                    .collect::<Vec<_>>(),
            )),
            Arc::new(StringArray::from(
                items
                    .iter()
                    .map(|item| item.updated_at.clone())
                    .collect::<Vec<_>>(),
            )),
        ],
    )?;
    batch_to_bytes(schema, batch)
}

fn users_to_bytes(items: &[User]) -> anyhow::Result<Vec<u8>> {
    let schema = Arc::new(Schema::new(vec![
        Field::new("id", DataType::Utf8, false),
        Field::new("username", DataType::Utf8, false),
        Field::new("password_hash", DataType::Utf8, false),
        Field::new("role", DataType::Utf8, false),
        Field::new("org_id", DataType::Utf8, true),
        Field::new("tree_key_enabled", DataType::Boolean, false),
        Field::new("active", DataType::Boolean, false),
        Field::new("created_at", DataType::Utf8, false),
    ]));
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(StringArray::from(
                items.iter().map(|item| item.id.clone()).collect::<Vec<_>>(),
            )),
            Arc::new(StringArray::from(
                items
                    .iter()
                    .map(|item| item.username.clone())
                    .collect::<Vec<_>>(),
            )),
            Arc::new(StringArray::from(
                items
                    .iter()
                    .map(|item| item.password_hash.clone())
                    .collect::<Vec<_>>(),
            )),
            Arc::new(StringArray::from(
                items
                    .iter()
                    .map(|item| item.role.as_str().to_owned())
                    .collect::<Vec<_>>(),
            )),
            Arc::new(StringArray::from(
                items
                    .iter()
                    .map(|item| item.org_id.clone())
                    .collect::<Vec<_>>(),
            )),
            Arc::new(BooleanArray::from(
                items
                    .iter()
                    .map(|item| item.tree_key_enabled)
                    .collect::<Vec<_>>(),
            )),
            Arc::new(BooleanArray::from(
                items.iter().map(|item| item.active).collect::<Vec<_>>(),
            )),
            Arc::new(StringArray::from(
                items
                    .iter()
                    .map(|item| item.created_at.clone())
                    .collect::<Vec<_>>(),
            )),
        ],
    )?;
    batch_to_bytes(schema, batch)
}

fn members_to_bytes(items: &[Member]) -> anyhow::Result<Vec<u8>> {
    let schema = Arc::new(Schema::new(vec![
        Field::new("id", DataType::Utf8, false),
        Field::new("org_id", DataType::Utf8, false),
        Field::new("full_name", DataType::Utf8, false),
        Field::new("title", DataType::Utf8, false),
        Field::new("year", DataType::Int32, false),
        Field::new("active", DataType::Boolean, false),
        Field::new("notes", DataType::Utf8, false),
        Field::new("birth_date", DataType::Utf8, false),
        Field::new("address", DataType::Utf8, false),
        Field::new("phone", DataType::Utf8, false),
        Field::new("joined_at", DataType::Utf8, false),
        Field::new("updated_at", DataType::Utf8, false),
    ]));
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(StringArray::from(
                items.iter().map(|item| item.id.clone()).collect::<Vec<_>>(),
            )),
            Arc::new(StringArray::from(
                items
                    .iter()
                    .map(|item| item.org_id.clone())
                    .collect::<Vec<_>>(),
            )),
            Arc::new(StringArray::from(
                items
                    .iter()
                    .map(|item| item.full_name.clone())
                    .collect::<Vec<_>>(),
            )),
            Arc::new(StringArray::from(
                items
                    .iter()
                    .map(|item| item.title.clone())
                    .collect::<Vec<_>>(),
            )),
            Arc::new(Int32Array::from(
                items.iter().map(|item| item.year).collect::<Vec<_>>(),
            )),
            Arc::new(BooleanArray::from(
                items.iter().map(|item| item.active).collect::<Vec<_>>(),
            )),
            Arc::new(StringArray::from(
                items
                    .iter()
                    .map(|item| item.notes.clone())
                    .collect::<Vec<_>>(),
            )),
            Arc::new(StringArray::from(
                items
                    .iter()
                    .map(|item| item.birth_date.clone())
                    .collect::<Vec<_>>(),
            )),
            Arc::new(StringArray::from(
                items
                    .iter()
                    .map(|item| item.address.clone())
                    .collect::<Vec<_>>(),
            )),
            Arc::new(StringArray::from(
                items
                    .iter()
                    .map(|item| item.phone.clone())
                    .collect::<Vec<_>>(),
            )),
            Arc::new(StringArray::from(
                items
                    .iter()
                    .map(|item| item.joined_at.clone())
                    .collect::<Vec<_>>(),
            )),
            Arc::new(StringArray::from(
                items
                    .iter()
                    .map(|item| item.updated_at.clone())
                    .collect::<Vec<_>>(),
            )),
        ],
    )?;
    batch_to_bytes(schema, batch)
}

fn activities_to_bytes(items: &[Activity]) -> anyhow::Result<Vec<u8>> {
    let schema = Arc::new(Schema::new(vec![
        Field::new("id", DataType::Utf8, false),
        Field::new("org_id", DataType::Utf8, false),
        Field::new("title", DataType::Utf8, false),
        Field::new("year", DataType::Int32, false),
        Field::new("status", DataType::Utf8, false),
        Field::new("summary", DataType::Utf8, false),
        Field::new("reviewed", DataType::Boolean, false),
        Field::new("updated_at", DataType::Utf8, false),
    ]));
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(StringArray::from(
                items.iter().map(|item| item.id.clone()).collect::<Vec<_>>(),
            )),
            Arc::new(StringArray::from(
                items
                    .iter()
                    .map(|item| item.org_id.clone())
                    .collect::<Vec<_>>(),
            )),
            Arc::new(StringArray::from(
                items
                    .iter()
                    .map(|item| item.title.clone())
                    .collect::<Vec<_>>(),
            )),
            Arc::new(Int32Array::from(
                items.iter().map(|item| item.year).collect::<Vec<_>>(),
            )),
            Arc::new(StringArray::from(
                items
                    .iter()
                    .map(|item| item.status.as_str().to_owned())
                    .collect::<Vec<_>>(),
            )),
            Arc::new(StringArray::from(
                items
                    .iter()
                    .map(|item| item.summary.clone())
                    .collect::<Vec<_>>(),
            )),
            Arc::new(BooleanArray::from(
                items.iter().map(|item| item.reviewed).collect::<Vec<_>>(),
            )),
            Arc::new(StringArray::from(
                items
                    .iter()
                    .map(|item| item.updated_at.clone())
                    .collect::<Vec<_>>(),
            )),
        ],
    )?;
    batch_to_bytes(schema, batch)
}

fn documents_to_bytes(items: &[Document]) -> anyhow::Result<Vec<u8>> {
    let schema = Arc::new(Schema::new(vec![
        Field::new("id", DataType::Utf8, false),
        Field::new("org_id", DataType::Utf8, false),
        Field::new("title", DataType::Utf8, false),
        Field::new("file_name", DataType::Utf8, false),
        Field::new("mime_type", DataType::Utf8, false),
        Field::new("preview_text", DataType::Utf8, false),
        Field::new("year", DataType::Int32, false),
        Field::new("encrypted_path", DataType::Utf8, false),
        Field::new("kem_ciphertext_b64", DataType::Utf8, false),
        Field::new("nonce_b64", DataType::Utf8, false),
        Field::new("uploaded_at", DataType::Utf8, false),
        Field::new("updated_at", DataType::Utf8, false),
    ]));
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(StringArray::from(
                items.iter().map(|item| item.id.clone()).collect::<Vec<_>>(),
            )),
            Arc::new(StringArray::from(
                items
                    .iter()
                    .map(|item| item.org_id.clone())
                    .collect::<Vec<_>>(),
            )),
            Arc::new(StringArray::from(
                items
                    .iter()
                    .map(|item| item.title.clone())
                    .collect::<Vec<_>>(),
            )),
            Arc::new(StringArray::from(
                items
                    .iter()
                    .map(|item| item.file_name.clone())
                    .collect::<Vec<_>>(),
            )),
            Arc::new(StringArray::from(
                items
                    .iter()
                    .map(|item| item.mime_type.clone())
                    .collect::<Vec<_>>(),
            )),
            Arc::new(StringArray::from(
                items
                    .iter()
                    .map(|item| item.preview_text.clone())
                    .collect::<Vec<_>>(),
            )),
            Arc::new(Int32Array::from(
                items.iter().map(|item| item.year).collect::<Vec<_>>(),
            )),
            Arc::new(StringArray::from(
                items
                    .iter()
                    .map(|item| item.encrypted_path.clone())
                    .collect::<Vec<_>>(),
            )),
            Arc::new(StringArray::from(
                items
                    .iter()
                    .map(|item| item.kem_ciphertext_b64.clone())
                    .collect::<Vec<_>>(),
            )),
            Arc::new(StringArray::from(
                items
                    .iter()
                    .map(|item| item.nonce_b64.clone())
                    .collect::<Vec<_>>(),
            )),
            Arc::new(StringArray::from(
                items
                    .iter()
                    .map(|item| item.uploaded_at.clone())
                    .collect::<Vec<_>>(),
            )),
            Arc::new(StringArray::from(
                items
                    .iter()
                    .map(|item| item.updated_at.clone())
                    .collect::<Vec<_>>(),
            )),
        ],
    )?;
    batch_to_bytes(schema, batch)
}

fn batch_to_bytes(schema: Arc<Schema>, batch: RecordBatch) -> anyhow::Result<Vec<u8>> {
    let mut cursor = Cursor::new(Vec::new());
    {
        let mut writer = FileWriter::try_new(&mut cursor, &schema)?;
        writer.write(&batch)?;
        writer.finish()?;
    }
    Ok(cursor.into_inner())
}

fn bytes_to_orgs(bytes: Vec<u8>) -> anyhow::Result<Vec<Organization>> {
    let batch = read_single_batch(bytes)?;
    let ids = column_string(&batch, 0)?;
    let parent_ids = column_opt_string(&batch, 1)?;
    let names = column_string(&batch, 2)?;
    let tiers = column_u32(&batch, 3)?;
    let categories = column_string(&batch, 4)?;
    let actives = column_bool(&batch, 5)?;
    let created = column_string(&batch, 6)?;
    let updated = column_string(&batch, 7)?;
    Ok((0..batch.num_rows())
        .map(|index| Organization {
            id: ids[index].clone(),
            parent_id: parent_ids[index].clone(),
            name: names[index].clone(),
            tier: tiers[index],
            category: categories[index].clone(),
            active: actives[index],
            created_at: created[index].clone(),
            updated_at: updated[index].clone(),
        })
        .collect())
}

fn bytes_to_users(bytes: Vec<u8>) -> anyhow::Result<Vec<User>> {
    let batch = read_single_batch(bytes)?;
    let ids = column_string(&batch, 0)?;
    let usernames = column_string(&batch, 1)?;
    let password_hashes = column_string(&batch, 2)?;
    let has_password_plain = batch.num_columns() >= 9;
    let role_index = if has_password_plain { 4 } else { 3 };
    let org_index = if has_password_plain { 5 } else { 4 };
    let tree_index = if has_password_plain { 6 } else { 5 };
    let active_index = if has_password_plain { 7 } else { 6 };
    let created_index = if has_password_plain { 8 } else { 7 };
    let roles = column_string(&batch, role_index)?;
    let org_ids = column_opt_string(&batch, org_index)?;
    let tree_keys = column_bool(&batch, tree_index)?;
    let actives = column_bool(&batch, active_index)?;
    let created = column_string(&batch, created_index)?;
    Ok((0..batch.num_rows())
        .map(|index| User {
            id: ids[index].clone(),
            username: usernames[index].clone(),
            password_hash: password_hashes[index].clone(),
            role: UserRole::from_value(&roles[index]),
            org_id: org_ids[index].clone(),
            tree_key_enabled: tree_keys[index],
            active: actives[index],
            created_at: created[index].clone(),
        })
        .collect())
}

fn bytes_to_members(bytes: Vec<u8>) -> anyhow::Result<Vec<Member>> {
    let batch = read_single_batch(bytes)?;
    let ids = column_string(&batch, 0)?;
    let org_ids = column_string(&batch, 1)?;
    let names = column_string(&batch, 2)?;
    let titles = column_string(&batch, 3)?;
    let years = column_i32(&batch, 4)?;
    let actives = column_bool(&batch, 5)?;
    let notes = column_string(&batch, 6)?;
    let rows = batch.num_rows();
    let birth_dates = if batch.num_columns() >= 12 {
        column_string(&batch, 7)?
    } else {
        vec![String::new(); rows]
    };
    let addresses = if batch.num_columns() >= 12 {
        column_string(&batch, 8)?
    } else {
        vec![String::new(); rows]
    };
    let phones = if batch.num_columns() >= 12 {
        column_string(&batch, 9)?
    } else {
        vec![String::new(); rows]
    };
    let joined_at = if batch.num_columns() >= 12 {
        column_string(&batch, 10)?
    } else {
        years.iter().map(|year| format!("{}-01-01", year)).collect()
    };
    let updated = if batch.num_columns() >= 12 {
        column_string(&batch, 11)?
    } else {
        column_string(&batch, 7)?
    };
    Ok((0..batch.num_rows())
        .map(|index| Member {
            id: ids[index].clone(),
            org_id: org_ids[index].clone(),
            full_name: names[index].clone(),
            title: titles[index].clone(),
            year: years[index],
            active: actives[index],
            notes: notes[index].clone(),
            birth_date: birth_dates[index].clone(),
            address: addresses[index].clone(),
            phone: phones[index].clone(),
            joined_at: joined_at[index].clone(),
            updated_at: updated[index].clone(),
        })
        .collect())
}

fn bytes_to_activities(bytes: Vec<u8>) -> anyhow::Result<Vec<Activity>> {
    let batch = read_single_batch(bytes)?;
    let ids = column_string(&batch, 0)?;
    let org_ids = column_string(&batch, 1)?;
    let titles = column_string(&batch, 2)?;
    let years = column_i32(&batch, 3)?;
    let statuses = column_string(&batch, 4)?;
    let summaries = column_string(&batch, 5)?;
    let reviewed = column_bool(&batch, 6)?;
    let updated = column_string(&batch, 7)?;
    Ok((0..batch.num_rows())
        .map(|index| Activity {
            id: ids[index].clone(),
            org_id: org_ids[index].clone(),
            title: titles[index].clone(),
            year: years[index],
            status: ActivityStatus::from_value(&statuses[index]),
            summary: summaries[index].clone(),
            reviewed: reviewed[index],
            updated_at: updated[index].clone(),
        })
        .collect())
}

fn bytes_to_documents(bytes: Vec<u8>) -> anyhow::Result<Vec<Document>> {
    let batch = read_single_batch(bytes)?;
    let ids = column_string(&batch, 0)?;
    let org_ids = column_string(&batch, 1)?;
    let titles = column_string(&batch, 2)?;
    let rows = batch.num_rows();
    let (
        file_names,
        mime_types,
        preview_texts,
        years_col,
        path_col,
        kem_col,
        nonce_col,
        uploaded_col,
        updated_col,
    ) = if batch.num_columns() >= 12 {
        (
            column_string(&batch, 3)?,
            column_string(&batch, 4)?,
            column_string(&batch, 5)?,
            6,
            7,
            8,
            9,
            10,
            Some(11),
        )
    } else if batch.num_columns() >= 11 {
        (
            column_string(&batch, 3)?,
            column_string(&batch, 4)?,
            column_string(&batch, 5)?,
            6,
            7,
            8,
            9,
            10,
            None,
        )
    } else {
        (
            titles.clone(),
            vec!["application/octet-stream".to_owned(); rows],
            vec![String::new(); rows],
            3,
            4,
            5,
            6,
            7,
            None,
        )
    };
    let years = column_i32(&batch, years_col)?;
    let paths = column_string(&batch, path_col)?;
    let kem_ciphertexts = column_string(&batch, kem_col)?;
    let nonces = column_string(&batch, nonce_col)?;
    let uploaded = column_string(&batch, uploaded_col)?;
    let updated = match updated_col {
        Some(index) => column_string(&batch, index)?,
        None => uploaded.clone(),
    };
    Ok((0..batch.num_rows())
        .map(|index| Document {
            id: ids[index].clone(),
            org_id: org_ids[index].clone(),
            title: titles[index].clone(),
            file_name: file_names[index].clone(),
            mime_type: mime_types[index].clone(),
            preview_text: preview_texts[index].clone(),
            year: years[index],
            encrypted_path: paths[index].clone(),
            kem_ciphertext_b64: kem_ciphertexts[index].clone(),
            nonce_b64: nonces[index].clone(),
            uploaded_at: uploaded[index].clone(),
            updated_at: updated[index].clone(),
        })
        .collect())
}

fn read_single_batch(bytes: Vec<u8>) -> anyhow::Result<RecordBatch> {
    let reader = FileReader::try_new(Cursor::new(bytes), None)?;
    let batches = reader.collect::<Result<Vec<_>, _>>()?;
    batches
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("missing feather batch"))
}

fn column_string(batch: &RecordBatch, index: usize) -> anyhow::Result<Vec<String>> {
    let Some(array) = batch.column(index).as_any().downcast_ref::<StringArray>() else {
        return Err(anyhow!("unexpected string column"));
    };
    Ok((0..batch.num_rows())
        .map(|row| array.value(row).to_owned())
        .collect())
}

fn column_opt_string(batch: &RecordBatch, index: usize) -> anyhow::Result<Vec<Option<String>>> {
    let Some(array) = batch.column(index).as_any().downcast_ref::<StringArray>() else {
        return Err(anyhow!("unexpected optional string column"));
    };
    Ok((0..batch.num_rows())
        .map(|row| {
            if array.is_null(row) {
                None
            } else {
                Some(array.value(row).to_owned())
            }
        })
        .collect())
}

fn column_bool(batch: &RecordBatch, index: usize) -> anyhow::Result<Vec<bool>> {
    let Some(array) = batch.column(index).as_any().downcast_ref::<BooleanArray>() else {
        return Err(anyhow!("unexpected bool column"));
    };
    Ok((0..batch.num_rows()).map(|row| array.value(row)).collect())
}

fn column_u32(batch: &RecordBatch, index: usize) -> anyhow::Result<Vec<u32>> {
    let Some(array) = batch.column(index).as_any().downcast_ref::<UInt32Array>() else {
        return Err(anyhow!("unexpected u32 column"));
    };
    Ok((0..batch.num_rows()).map(|row| array.value(row)).collect())
}

fn column_i32(batch: &RecordBatch, index: usize) -> anyhow::Result<Vec<i32>> {
    let Some(array) = batch.column(index).as_any().downcast_ref::<Int32Array>() else {
        return Err(anyhow!("unexpected i32 column"));
    };
    Ok((0..batch.num_rows()).map(|row| array.value(row)).collect())
}
