use chrono::Utc;
use common::firestore::{COLLECTION_FUNCTIONS, COLLECTION_GROUPS, COLLECTION_USERS};
use common::models::{Attributes, FunctionInfo, GroupInfo, GroupMember, GroupMembership};
use firestore::{FirestoreDb, FirestoreResult};
use futures::stream::TryStreamExt;
use uuid::Uuid;

pub enum GrantTarget {
    Group(String),
    User(Uuid),
}

pub async fn upsert_function(
    db: &FirestoreDb,
    function_id: &str,
    name: &str,
    description: &str,
) -> FirestoreResult<()> {
    let info = FunctionInfo {
        function_id: None,
        name: name.to_string(),
        description: description.to_string(),
        created_at: Utc::now(),
    };
    db.fluent()
        .update()
        .in_col(COLLECTION_FUNCTIONS)
        .document_id(function_id)
        .object(&info)
        .execute::<FunctionInfo>()
        .await?;
    Ok(())
}

pub async fn list_functions(db: &FirestoreDb) -> FirestoreResult<Vec<FunctionInfo>> {
    db.fluent()
        .list()
        .from(COLLECTION_FUNCTIONS)
        .obj()
        .stream_all_with_errors()
        .await?
        .try_collect()
        .await
}

pub async fn upsert_group(db: &FirestoreDb, group_id: &str, name: &str) -> FirestoreResult<()> {
    let info = GroupInfo {
        group_id: None,
        name: name.to_string(),
        created_at: Utc::now(),
    };
    db.fluent()
        .update()
        .in_col(COLLECTION_GROUPS)
        .document_id(group_id)
        .object(&info)
        .execute::<GroupInfo>()
        .await?;
    Ok(())
}

pub async fn list_groups(db: &FirestoreDb) -> FirestoreResult<Vec<GroupInfo>> {
    db.fluent()
        .list()
        .from(COLLECTION_GROUPS)
        .obj()
        .stream_all_with_errors()
        .await?
        .try_collect()
        .await
}

/// Writes both `users/{user_id}/groups/{group_id}` and
/// `groups/{group_id}/members/{user_id}` — not wrapped in a transaction,
/// same "not fully transactional, acceptable for now" tradeoff already
/// made in `registration`'s `complete_registration`.
pub async fn add_group_member(
    db: &FirestoreDb,
    group_id: &str,
    user_id: Uuid,
) -> FirestoreResult<()> {
    let user_groups_parent = db.parent_path(COLLECTION_USERS, user_id.to_string())?;
    db.fluent()
        .update()
        .in_col(COLLECTION_GROUPS)
        .document_id(group_id)
        .parent(&user_groups_parent)
        .object(&GroupMembership::default())
        .execute::<GroupMembership>()
        .await?;

    let group_members_parent = db.parent_path(COLLECTION_GROUPS, group_id)?;
    db.fluent()
        .update()
        .in_col(COLLECTION_USERS)
        .document_id(user_id.to_string())
        .parent(&group_members_parent)
        .object(&GroupMember::default())
        .execute::<GroupMember>()
        .await?;

    Ok(())
}

pub async fn remove_group_member(
    db: &FirestoreDb,
    group_id: &str,
    user_id: Uuid,
) -> FirestoreResult<()> {
    let user_groups_parent = db.parent_path(COLLECTION_USERS, user_id.to_string())?;
    db.fluent()
        .delete()
        .from(COLLECTION_GROUPS)
        .document_id(group_id)
        .parent(&user_groups_parent)
        .execute()
        .await?;

    let group_members_parent = db.parent_path(COLLECTION_GROUPS, group_id)?;
    db.fluent()
        .delete()
        .from(COLLECTION_USERS)
        .document_id(user_id.to_string())
        .parent(&group_members_parent)
        .execute()
        .await?;

    Ok(())
}

pub async fn list_group_members(db: &FirestoreDb, group_id: &str) -> FirestoreResult<Vec<Uuid>> {
    let parent = db.parent_path(COLLECTION_GROUPS, group_id)?;
    let members: Vec<GroupMember> = db
        .fluent()
        .list()
        .from(COLLECTION_USERS)
        .parent(&parent)
        .obj()
        .stream_all_with_errors()
        .await?
        .try_collect()
        .await?;
    Ok(members.into_iter().filter_map(|m| m.user_id).collect())
}

fn grant_collection_and_id(target: &GrantTarget) -> (&'static str, String) {
    match target {
        GrantTarget::Group(group_id) => (COLLECTION_GROUPS, group_id.clone()),
        GrantTarget::User(user_id) => (COLLECTION_USERS, user_id.to_string()),
    }
}

pub async fn set_grant(
    db: &FirestoreDb,
    function_id: &str,
    target: &GrantTarget,
    attributes: &Attributes,
) -> FirestoreResult<()> {
    let parent = db.parent_path(COLLECTION_FUNCTIONS, function_id)?;
    let (collection, doc_id) = grant_collection_and_id(target);
    db.fluent()
        .update()
        .in_col(collection)
        .document_id(doc_id)
        .parent(&parent)
        .object(attributes)
        .execute::<Attributes>()
        .await?;
    Ok(())
}

pub async fn revoke_grant(
    db: &FirestoreDb,
    function_id: &str,
    target: &GrantTarget,
) -> FirestoreResult<()> {
    let parent = db.parent_path(COLLECTION_FUNCTIONS, function_id)?;
    let (collection, doc_id) = grant_collection_and_id(target);
    db.fluent()
        .delete()
        .from(collection)
        .document_id(doc_id)
        .parent(&parent)
        .execute()
        .await?;
    Ok(())
}

pub struct Grants {
    pub groups: Vec<(String, Attributes)>,
    pub users: Vec<(Uuid, Attributes)>,
}

pub async fn list_grants(db: &FirestoreDb, function_id: &str) -> FirestoreResult<Grants> {
    let parent = db.parent_path(COLLECTION_FUNCTIONS, function_id)?;

    let group_memberships: Vec<GroupMembership> = db
        .fluent()
        .list()
        .from(COLLECTION_GROUPS)
        .parent(&parent)
        .obj()
        .stream_all_with_errors()
        .await?
        .try_collect()
        .await?;
    let mut groups = Vec::new();
    for membership in group_memberships {
        if let Some(group_id) = membership.group_id
            && let Some(attrs) = get_attributes(db, COLLECTION_GROUPS, &parent, &group_id).await?
        {
            groups.push((group_id, attrs));
        }
    }

    let user_overrides: Vec<GroupMember> = db
        .fluent()
        .list()
        .from(COLLECTION_USERS)
        .parent(&parent)
        .obj()
        .stream_all_with_errors()
        .await?
        .try_collect()
        .await?;
    let mut users = Vec::new();
    for member in user_overrides {
        if let Some(user_id) = member.user_id
            && let Some(attrs) =
                get_attributes(db, COLLECTION_USERS, &parent, &user_id.to_string()).await?
        {
            users.push((user_id, attrs));
        }
    }

    Ok(Grants { groups, users })
}

async fn get_attributes(
    db: &FirestoreDb,
    collection: &str,
    parent: &firestore::ParentPathBuilder,
    doc_id: &str,
) -> FirestoreResult<Option<Attributes>> {
    db.fluent()
        .select()
        .by_id_in(collection)
        .parent(parent)
        .obj()
        .one(doc_id)
        .await
}
