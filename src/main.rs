use axum::{
    extract::Json,
    extract::MatchedPath,
    http::Request
};
use axum::extract::State;
use axum::http::{Method, StatusCode};
use axum::response::IntoResponse;
use axum::Router;
use axum::routing::post;
use cf_turnstile::{SiteVerifyRequest, TurnstileClient};
use dotenv::dotenv;
use envconfig::Envconfig;
use lettre::{Message, SmtpTransport, Transport};
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::{Credentials, Mechanism};
use lettre::transport::smtp::client::Tls;
use listenfd::ListenFd;
use serde_derive::Deserialize;
use tokio::net::TcpListener;
use tower_http::cors::{AllowHeaders, Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::info_span;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[derive(Clone, Envconfig)]
struct Config {
    #[envconfig(from = "CF_SECRET")]
    cf_secret: String,

    #[envconfig(from = "TO_ADDRESS")]
    to_address: String,
    #[envconfig(from = "FROM_ADDRESS")]
    from_address: String,

    #[envconfig(from = "SMTP_USERNAME")]
    smtp_username: String,
    #[envconfig(from = "SMTP_PASSWORD")]
    smtp_password: String,
    #[envconfig(from = "SMTP_HOST")]
    smtp_host: String
}

#[derive(Clone)]
struct AppState {
    config: Config
}

impl AppState {
    fn from_config(config: Config) -> AppState {
        AppState {
            config
        }
    }
}

#[tokio::main]
async fn main() {
    dotenv().ok();

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
               "contact_api=trace,tower_http=debug,axum::rejection=trace".into()
            }),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let state = AppState::from_config(Config::init_from_env().unwrap());

    tracing::debug!("CF_SECRET: {}", state.config.cf_secret);
    tracing::debug!("TO_ADDRESS: {}", state.config.to_address);
    tracing::debug!("FROM_ADDRESS: {}", state.config.from_address);
    tracing::debug!("SMTP: {}:{}@{}", state.config.smtp_username, state.config.smtp_password, state.config.smtp_host);

    let mut listenfd = ListenFd::from_env();

    let app = Router::new().route("/email", post(handler))
        .fallback(fallback)
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|request: &Request<_>| {
                    // Log the matched route's path (with placeholders not filled in).
                    // Use request.uri() or OriginalUri if you want the real path.
                    let matched_path = request
                        .extensions()
                        .get::<MatchedPath>()
                        .map(MatchedPath::as_str);

                    info_span!(
                        "http_request",
                        method = ?request.method(),
                        matched_path
                    )
                })
        )
        .layer(CorsLayer::new().allow_methods([Method::POST]).allow_origin(Any).allow_headers(AllowHeaders::any()))
        .with_state(state);

    let listener = match listenfd.take_tcp_listener(0).unwrap() {
        // if we are given a tcp listener on listen fd 0, we use that one
        Some(listener) => {
            listener.set_nonblocking(true).unwrap();
            TcpListener::from_std(listener).unwrap()
        }
        // otherwise fall back to local listening
        None => TcpListener::bind("0.0.0.0:2536").await.unwrap(),
    };

    tracing::info!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}

#[derive(Deserialize)]
struct EmailData {
    cf_token: String,
    from: String,
    address_1: String,
    address_2: String,
    city: String,
    county: String,
    postal_code: String,
    mobile: String,
    query: String,
    name: String
}

async fn handler(State(state): State<AppState>, Json(payload): Json<EmailData>) -> impl IntoResponse {
    let client = TurnstileClient::new(state.config.cf_secret.into());

    if let Err(e) = client.siteverify(SiteVerifyRequest {
        response: payload.cf_token,
        ..Default::default()
    }).await {
        tracing::debug!("{}", e);
        return (StatusCode::UNAUTHORIZED, "");
    }

    tracing::trace!("Token authorised");

    let smtp_credentials = Credentials::new(state.config.smtp_username, state.config.smtp_password);

    let relay = SmtpTransport::relay(&*state.config.smtp_host);
    if let Err(e) = relay {
        tracing::debug!("smtp relay error: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, "smtp failure");
    }
    let relay = relay.unwrap().credentials(smtp_credentials).tls(Tls::None).port(25).build();
    tracing::trace!("Created relay");

    let body = format!(r#"You have a new query.

    <b>Name:</b> {}
    <b>Email:</b> {}
    <b>Number:</b> {}
    <b>Address:</b>
    {}
    {}
    {}
    {}
    {}

    <b>Query:</b> {}"#, payload.name, payload.from, payload.mobile, payload.address_1, payload.address_2, payload.city, payload.county, payload.postal_code, payload.query);

    let body = body.replace("\n", "<br>");

    let email = Message::builder()
        .from(state.config.from_address.parse().unwrap())
        .reply_to(payload.from.parse().unwrap())
        .to(state.config.to_address.parse().unwrap())
        .subject("New Query")
        .header(ContentType::TEXT_HTML)
        .body(body)
        .unwrap();

    if let Err(e) = relay.send(&email) {
        tracing::debug!("error sending message {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, "smtp send failure");
    }

    (StatusCode::OK, "")
}

async fn fallback() -> impl IntoResponse {
    StatusCode::NOT_FOUND
}
