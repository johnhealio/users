use common::Config;
use webauthn_rs::prelude::{Url, Webauthn, WebauthnBuilder};

pub fn build(config: &Config) -> Webauthn {
    let rp_origin = Url::parse(&config.rp_origin).expect("RP_ORIGIN must be a valid URL");
    WebauthnBuilder::new(&config.rp_id, &rp_origin)
        .expect("rp_id must be an effective domain of rp_origin")
        .rp_name("johnheal.io")
        .build()
        .expect("failed to build Webauthn instance")
}
