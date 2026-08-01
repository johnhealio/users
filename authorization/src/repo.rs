use common::firestore::{COLLECTION_FUNCTIONS, COLLECTION_GROUPS, COLLECTION_USERS};
use common::models::{Attributes, GroupMembership};
use firestore::{FirestoreDb, FirestoreResult};
use futures::stream::TryStreamExt;
use uuid::Uuid;

/// Resolves what `user_id` is granted for `function_id`, or `None` if
/// nothing grants them access at all.
///
/// Base attributes come from the first of the user's groups that has a
/// `functions/{function_id}/groups/{group_id}` doc (first match wins if a
/// user is in more than one permitted group — multi-group precedence isn't
/// designed yet). A `functions/{function_id}/users/{user_id}` doc, if
/// present, has its keys merged **over** that base (or stands alone if
/// there's no permitted group at all).
pub async fn resolve_access(
    db: &FirestoreDb,
    user_id: Uuid,
    function_id: &str,
) -> FirestoreResult<Option<Attributes>> {
    let user_groups_path = db.parent_path(COLLECTION_USERS, user_id.to_string())?;
    let memberships: Vec<GroupMembership> = db
        .fluent()
        .list()
        .from(COLLECTION_GROUPS)
        .parent(&user_groups_path)
        .obj()
        .stream_all_with_errors()
        .await?
        .try_collect()
        .await?;
    let group_ids: Vec<String> = memberships.into_iter().filter_map(|m| m.group_id).collect();

    let function_path = db.parent_path(COLLECTION_FUNCTIONS, function_id)?;

    let mut base: Option<Attributes> = None;
    for group_id in &group_ids {
        let attrs: Option<Attributes> = db
            .fluent()
            .select()
            .by_id_in(COLLECTION_GROUPS)
            .parent(&function_path)
            .obj()
            .one(group_id)
            .await?;
        if attrs.is_some() {
            base = attrs;
            break;
        }
    }

    let user_override: Option<Attributes> = db
        .fluent()
        .select()
        .by_id_in(COLLECTION_USERS)
        .parent(&function_path)
        .obj()
        .one(&user_id.to_string())
        .await?;

    Ok(match (base, user_override) {
        (None, None) => None,
        (base, Some(override_attrs)) => {
            let mut merged = base.unwrap_or_default();
            merged.extend(override_attrs);
            Some(merged)
        }
        (Some(base), None) => Some(base),
    })
}
