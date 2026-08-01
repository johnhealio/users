use common::firestore::COLLECTION_SESSIONS;
use firestore::{FirestoreDb, FirestoreResult};

pub async fn delete_session(db: &FirestoreDb, token_hash: &str) -> FirestoreResult<()> {
    db.fluent()
        .delete()
        .from(COLLECTION_SESSIONS)
        .document_id(token_hash)
        .execute()
        .await
}
