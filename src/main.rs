use axum::{
    body::Body as AxumBody,
    extract::{Path, State},
    http::Request,
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use axum_session::{SessionConfig, SessionLayer, SessionStore};
use axum_session_auth::{AuthConfig, AuthSessionLayer, SessionSqlitePool};
use leptos::{get_configuration, logging::log, provide_context};
use leptos_axum::{
    generate_route_list, handle_server_fns_with_context, LeptosRoutes,
};
use leptos_liv::{
    auth::{ssr::AuthSession, User},
    fallback::file_and_error_handler,
    state::AppState,
    todo::*,
};
use sqlx::{sqlite::SqlitePoolOptions, SqlitePool};

use tokio::time::{sleep, Duration};

async fn server_fn_handler(
    State(app_state): State<AppState>,
    auth_session: AuthSession,
    path: Path<String>,
    request: Request<AxumBody>,
) -> impl IntoResponse {
    log!("{:?}", path);

    handle_server_fns_with_context(
        move || {
            provide_context(auth_session.clone());
            provide_context(app_state.pool.clone());
        },
        request,
    )
    .await
}

async fn leptos_routes_handler(
    auth_session: AuthSession,
    State(app_state): State<AppState>,
    req: Request<AxumBody>,
) -> Response {
    let handler = leptos_axum::render_route_with_context(
        app_state.leptos_options.clone(),
        app_state.routes.clone(),
        move || {
            provide_context(auth_session.clone());
            provide_context(app_state.pool.clone());
        },
        TodoApp,
    );
    handler(req).await.into_response()
}

#[tokio::main]
async fn main() {
    simple_logger::init_with_level(log::Level::Info)
        .expect("couldn't initialize logging");

    // 开启定时任务
    tokio::spawn(async {
        // 读取当前系统的磁盘信息并写入数据库
        // df | grep /var/lib/docker/overlay2 | awk '{print $2}'
        loop {
            let mut sh = "sh";
            let mut p = "/var/lib/docker/overlay2";
            if cfg!(target_os = "linux") {
                sh = "sh";
            } else {
                sh = "cmd";
                p = "D:\\Code\\rust\\leptos_liv";
            }
            let output = std::process::Command::new(sh).arg("-c").args([
                "df | grep ",
                p,
                " | awk '{print $2}'",
            ]) 
            // .arg("df | grep D:\\Code\\rust\\leptos_liv | awk '{print $2}'")
            .output().expect("命令异常提示");
            let output_str = String::from_utf8(output.stdout);
            let u_32 = match output_str{
                Ok(output_str_d)=>{
                    let u_32_result = output_str_d.trim().parse::<u32>();  // 要转换的类型
                    match u_32_result {
                        Ok(u_32)=> {u_32}  // 将结果返回
                        Err(err)=>{0}
                    }
                }
                Err(err)=>{0}
            };
            println!("要获取的结果为:{}",u_32);
            sleep(Duration::from_secs(60)).await;
        }
    });

    let pool = SqlitePoolOptions::new()
        .connect("sqlite:Todos.db")
        .await
        .expect("Could not make pool.");

    // Auth section
    let session_config =
        SessionConfig::default().with_table_name("axum_sessions");
    let auth_config = AuthConfig::<i64>::default();
    let session_store = SessionStore::<SessionSqlitePool>::new(
        Some(pool.clone().into()),
        session_config,
    )
    .await
    .unwrap();

    if let Err(e) = sqlx::migrate!().run(&pool).await {
        eprintln!("{e:?}");
    }

    // Explicit server function registration is no longer required

    // Setting this to None means we'll be using cargo-leptos and its env vars
    let conf = get_configuration(None).await.unwrap();
    let leptos_options = conf.leptos_options;
    let addr = leptos_options.site_addr;
    let routes = generate_route_list(TodoApp);

    let app_state = AppState {
        leptos_options,
        pool: pool.clone(),
        routes: routes.clone(),
    };

    // build our application with a route
    let app = Router::new()
        .route(
            "/api/*fn_name",
            get(server_fn_handler).post(server_fn_handler),
        )
        .leptos_routes_with_handler(routes, get(leptos_routes_handler))
        .fallback(file_and_error_handler)
        .layer(
            AuthSessionLayer::<User, i64, SessionSqlitePool, SqlitePool>::new(
                Some(pool.clone()),
            )
            .with_config(auth_config),
        )
        .layer(SessionLayer::new(session_store))
        .with_state(app_state);

    // run our app with hyper
    // `axum::Server` is a re-export of `hyper::Server`
    log!("listening on http://{}", &addr);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app.into_make_service())
        .await
        .unwrap();
}
