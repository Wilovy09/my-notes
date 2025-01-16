---
title: 'Actix desde 0'
description: 'Aprendiendo Actix.rs desde 0'
pubDate: 'Sep 01 2024'
heroImage: '/actix-desde-0.png'
---

# Notas Actix

Estas son mis notas que fui haciendo mientras aprendia Actix para el desarrollo de APIs en Rust.

Puede que el código que encuentres aqui no sea de la mejor calidad pero fue la forma en la que aprendi a hacer las cosas al inicio.

## Pendientes

* [ ] Validar los datos que nos envian, no solo el tipo con el crate [validator](https://crates.io/crates/validator)
* [ ] Enviar correos de recuperación de contraseña, validar el correo, etc... con el crate [lettre](https://crates.io/crates/lettre)

## Como leer variables de un `.env`

Instalamos un paquete `dotenv`

```bash
cargo add dotenv
```

Creamos un archivo `.env` y definimos algunas variables en el

```env
URL=https://www.wilovy.com
NOMBRE=Wilovy
```

Ahora en nuestro `main.rs` pondremos lo siguiente:

```rust
use dotenv::dotenv; // esto es el paquete que instalamos
use std::env;

fn main() {
    dotenv().ok();

    let nombre = env::var("NOMBRE").expect("Falta NOMBRE");
    let url = env::var("URL").expect("Falta URL");

    println!("Nombre: {}, URL: {}", nombre, url)
}
```

## Estructura básica para iniciar una API

```bash
cargo install cargo-watch
```

```rust
use actix_web::{get, http::header, App, HttpResponse, HttpServer};

#[get("/")]
async fn test() -> HttpResponse {
    HttpResponse::Ok()
        .content_type(header::ContentType::json())
        .body(
            r#"
    {
        "ok": "ok"
    }
    "#,
        )
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| App::new().service(test))
        .bind(("127.0.0.1", 8080))?
        .run()
        .await
}
```

```bash
cargo watch -x run
```

## Parametros con struct

```rust
use actix_web::{get, http::header, web, HttpResponse};
use serde::Deserialize;

#[derive(Deserialize)]
struct Parametros {
    id: u8,
    estado: String,
}

// Esto es con Path Params
#[get("/usuarios/{id}/{estado}")]
async fn usuario(parametros: web::Path<Parametros>) -> HttpResponse {
    HttpsResponse::Ok()
        .content_type(header::ContentType::json())
        .body(format!(r#"
        {{
            "id": {},
            "estado": "{}"
        }}
        "#, parametros.id, parametros.estado))
}

// Esto es con Query Params
#[get("/usuario")]
async fn usuario(parametros: web::Query<Parametros>) -> HttpResponse {
    HttpResponse::Ok()
        .content_type(header::ContentType::json())
        .body(format!(
            r#"{{
            "id": {},
            "estado": "{}"
        }}"#,
            parametros.id, parametros.estado
        ))
}
```

## Procesar JSONS

Para recibir jsons en post o asi

```rust
use actix_web::{post, web, HttpResponse};
use serde::Deserialize;

#[derive(Deserialize)]
struct SumaParams {
    a: u8,
    b: u8,
    c: u8,
}

#[post("/suma")]
// Actix se encarga de validar el tipo segun la struct (web::Json<STRUCT_NAME>)
async fn suma(parametros: web::Json<SumaParams>) -> HttpResponse {
    let resultado = parametros.a + parametros.b + parametros.c;
    HttpResponse::Ok().body(format!("Resultado es: {}", resultado))
}
```

## URL Encoded forms

```rust
use actix_web::{post, web, HttpResponse};
use serde::Deserialize;

#[derive(Deserialize)]
struct Persona {
    nombre: String,
    apellido: String,
    edad: u8,
}

#[post("/persona")]
async fn persona(parametros: web::Form<Persona>) -> HttpResponse {
    HttpResponse::Ok().body(format!(
        "Tu nombre es: {} {}, tu edad es: {}",
        parametros.nombre, parametros.apellido, parametros.edad
    ))
}
```

## Responder con JSONs

```rust
use actix_web::{get, web, Responder};
use serde::Serialize;

// Se pueden incluir ambas, Serialize y Deserialize en una misma struct
#[derive(Serialize)]
struct Autor {
    id: u8,
    nombre: String,
    apellido: String,
}

#[get("/autor")]
async fn autor() -> impl Responder {
    let autor: Autor = Autor {
        id: 1,
        nombre: "Wilovy".to_string(),
        apellido: "Rust".to_string(),
    };

    web::Json(autor)
}
```

Pero si queremos cambiar el `status code`, tenemos que retornar un `HttpResponse`

```rust
use actix_web::{get, web, HttpResponse};
use serde::Serialize;

#[derive(Serialize)]
struct Autor {
    id: u8,
    nombre: String,
    apellido: String,
}

#[get("/autor")]
async fn autor() -> HttpResponse {
    let autor: Autor = Autor {
        id: 1,
        nombre: "Wilovy".to_string(),
        apellido: "Rust".to_string(),
    };

    // Para mantenerlo sencillo usaremos Created (201)
    HttpResponse::Created().json(autor)
}
```

Pero..., los JSONs que estamos regresando son muy sencillos, mejor intentemos hacer que regrese el autor con un listado de libros.

```rust
use actix_web::{get, web, HttpResponse};
use serde::Serialize;


#[derive(Serialize)]
struct Libros {
    id: u8,
    titulo: String
}

#[derive(Serialize)]
struct Autor {
    id: u8,
    nombre: String,
    apellido: String,
    libros: Vec<Libros>
}

#[get("/autor")]
async fn autor() -> HttpResponse {
    let autor: Autor = Autor {
        id: 1,
        nombre: "Wilovy".to_string(),
        apellido: "Rust".to_string(),
        libros: vec![
            Libros {
                id: 1,
                titulo: "Rust desde 0".to_string(),
            },
            Libros {
                id: 1,
                titulo: "Actix desde 0".to_string(),
            },
        ],
    };

    // Para mantenerlo sencillo usaremos Created
    HttpResponse::Created().json(autor)
}
```

## Subir archivos

### Un solo archivo

Para lograr esto tenemos que agregar a nuestro formulario de html el atributo `enctype='multipart/form-data'` e instalar unas dependencias a nuestro proyecto

```html
<form action="subir-archivo" method="post" enctype="multipart/form-data"></form>
```

```bash
cargo add actix-multipart
cargo add futures-util
```

Ahora si nuestro código

```rust
use actix_multipart::Multipart;
use actix_web::{post, web, Error, HttpResponse};
use futures_util::TryStreamExt;
use std::io::Write;

#[post("/subir-archivo")]
async fn subir_archivo(mut payload: Multipart) -> Result<HttpResponse, Error> {
    while let Some(mut field) = payload.try_next().await? {
        // Verificamos si content_disposition tiene un valor válido
        let Some(content_disposition) = field.content_disposition() else { continue; };

        let file_name = content_disposition
            .get_filename()
            .expect("Falta nombre al archivo.");
        /* Esta es la ruta donde se guardara el archivo que nos manden en el API
         * Esto significa que buscara una carpeta `assets` en la raiz de nuestro proyecto
         * A la misma altura que src, target, Cargo.toml
        */
        let file_path = format!("./assets/{file_name}");

        let mut archivo = web::block(|| std::fs::File::create(file_path)).await??;

        while let Some(chunk) = field.try_next().await? {
            archivo = web::block(move || archivo.write_all(&chunk).map(|_| archivo)).await??;
        }
    }
    Ok(HttpResponse::Ok().body("Archivo subido correctamente"))
}
```

Para probar nuestra API en un HttpClient (Insomnia) tenemos que irnos a `Body`>`Multipart form`> y en value seleccionar `file`

Un error que tiene esto, es que si se vuelve a enviar un archivo con el mismo nombre, se sobreescribe el archivo anterior.

### Subir mayor información, no solo un archivo

```rust
use actix_multipart::form::{tempfile::TempFile, text::Text, MultipartForm};
use actix_web::{post, web, Error, HttpResponse};

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(subir_archivos);
}

#[derive(Debug, MultipartForm)]
pub struct FormularioConArchivos {
    pub nombre: Text<String>,
    pub apellido: Text<String>,
    pub archivo: TempFile,
    // pub archivo2: TempFile,
}

#[post("/subir-archivos")]
async fn subir_archivos(
    MultipartForm(form): MultipartForm<FormularioConArchivos>,
) -> Result<HttpResponse, Error> {
    println!(
        "Nombre: {}, Apellido: {}",
        form.nombre.as_str(),
        form.apellido.as_str()
    );

    // Si fuera una lista de archivos seria hacer un loop
    let file_name = form.archivo.file_name.unwrap();
    let file_path = format!("./assets/{file_name}");
    form.archivo.file.persist(file_path).unwrap();

    Ok(HttpResponse::Ok().body("Archivo subidos correctamente"))
}
```

Y en nuestro HttpClient hariamos algo asi:

![Subir archivos con mas información](/actix/multipart_files.png)

El "problema" que tiene esto es que `MultipartForm` tiene un limite de subida, por defecto son `50mb` en total, si se manda más de `50mb` totales te dara un error donde se dice que se excedio el limite de memoria (error 400).

### Aumentar el espacio en memoria

```rust
// Importamos `MultipartFormConfig` de form
use actix_multipart::form::MultipartFormConfig;
use actix_web::{App, HttpServer};
mod routes;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        // Definos una constante para definir nuestros mb
        const MB: usize = 1024 /* 1024 es un kb */ * 1024 /* 1kb x 1024 = 1mb */ * 100 /* 1mb x 100 = 100mb */;
        // Definimos una variable para nuestra config
        let multipartform_config = MultipartFormConfig::default()
            // El tamaño de estos metodos es en `bytes`
            .total_limit(MB)
            .memory_limit(MB);
        App::new()
            .app_data(multipartform_config)
            //...code...
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
```

## Archivos estáticos y descargar archivos

Pra poder trabajar con archivos estaticos tenemos que instalar un paquete.

```bash
cargo add actix-files
```

Vamos a crear una carpeta en la raiz de nuestro proyecto `static/`

```txt
📁.
├──📄Cargo.lock
├──📄Cargo.toml
├──📄README.md
├──📁static
│  ├──📁css
│  ├──📁img
│  └──📁js
├──📁static
└──📁target
```

Con esto podriamos visualizar nuestros archivos estaticos.

```rust
use actix_files::NamedFile;
use actix_web::{get, Error, HttpRequest, Result};
use std::path::PathBuf;


#[get("/static/{filename:.*}")]
async fn archivos_estaticos(req: HttpRequest) -> Result<NamedFile, Error> {
    let pbuf: PathBuf = req.match_info().query("filename").parse().unwrap();
    let mut ruta = pbuf.into_os_string().into_string().unwrap();

    ruta = format!("./static/{ruta}");

    let archivo = NamedFile::open(ruta)?;

    Ok(archivo.use_last_modified(true))
}
```

Pero si queremos poder descargarlos debemos hacer una pequeña modificación:

```rust
use actix_files::NamedFile;
use actix_web::{get, http::header::ContentDisposition, Error, HttpRequest, Result};
use std::path::PathBuf;

#[get("/static/{filename:.*}")]
async fn archivos_estaticos(req: HttpRequest) -> Result<NamedFile, Error> {
    let pbuf: PathBuf = req.match_info().query("filename").parse().unwrap();
    let ruta = format!("./static/{}", pbuf.into_os_string().into_string().unwrap());

    let archivo = NamedFile::open(ruta.clone())?;

    Ok(archivo.set_content_disposition(ContentDisposition::attachment(ruta.clone().as_str())))
}
```

## Bases de datos - SQLx

Para entender como funciona esto, haremos una mini API que nos permitira entender como funciona `actix-web` con `sqlx`, para trbajar con SQLx debemos de instalar manualmente en nuestro `Cargo.toml` lo siguiente:

```toml
[dependencies]
sqlx = { version = "0.8.1", features = [ "runtime-async-std", "sqlite", "macros", "migrate" ] }
```

Ahora si podemos añadir las demas dependencias de forma normal

```bash
cargo add actix-web dotenv
```

```bash
cargo add serde -F derive
```

Adicionalmente podemos instalar el [CLI](https://github.com/launchbadge/sqlx/blob/main/sqlx-cli/README.md) que nos da sqlx:

```bash
cargo install sqlx-cli --no-default-features --features sqlite
```

Este [CLI](https://github.com/launchbadge/sqlx/blob/main/sqlx-cli/README.md) nos da facilidades al momento de crear migraciones con comandos como:

```bash
sqlx database create
sqlx database drop
sqlx migrate add NOMBRE_MIGRACIÓN
sqlx migrate run
```

Ahora debemos de crear un `.env` en el que definiremos nuestra variable de entorno.

```env
DATABASE_URL=sqlite://$PWD/temp/sqlx.db
```

Corremos el comando del CLI

```bash
sqlx database create
```

```rust
// src/main.rs
use actix_web::{web::Data, App, HttpServer};
use dotenv::dotenv;
use sqlx::{sqlite::SqlitePoolOptions, Pool, Sqlite};
mod services;
use services::{create_user_article, fetch_user_articles, fetch_users, create_user};

pub struct AppState {
    db: Pool<Sqlite>,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    let database_url = std::env::var("DATABASE_URL").expect("No se encontro DATABASE_URL");
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Error al crear la conexión a la base de dato");

    HttpServer::new(move || {
        App::new()
            .app_data(Data::new(AppState { db: pool.clone() }))
            .service(create_user)
            .service(fetch_users)
            .service(fetch_user_articles)
            .service(create_user_article)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
```

Creamos un archivo `services.rs` a la mista altura que `main.rs`

```rust
// src/services.rs
use crate::AppState;
use actix_web::{
    get, post,
    web::{Data, Json, Path},
    HttpResponse, Responder,
};
use serde::{Deserialize, Serialize};
use sqlx::{self, FromRow};

#[derive(Serialize, FromRow)]
struct User {
    id: i32,
    name: String,
    last_name: String,
}

#[derive(Serialize, FromRow)]
struct Article {
    id: i32,
    title: String,
    content: String,
    created_by: i32,
}

#[derive(Deserialize)]
pub struct CreateUserBody {
    name: String,
    last_name: String,
}

#[derive(Deserialize)]
pub struct CreateArticleBody {
    pub title: String,
    pub content: String,
}

#[get("/users")]
async fn fetch_users(state: Data<AppState>) -> impl Responder {
    match sqlx::query_as::<_, User>("SELECT id, name, last_name FROM users")
        .fetch_all(&state.db)
        .await
    {
        Ok(users) => HttpResponse::Ok().json(users),
        Err(_) => HttpResponse::NotFound().json("No users found"),
    }
}

#[post("/users")]
async fn create_user(state: Data<AppState>, body: Json<CreateUserBody>) -> impl Responder {
    match sqlx::query_as::<_, User>(
        "INSERT INTO users (name, last_name) VALUES ($1, $2) RETURNING id, name, last_name",
    )
    .bind(body.name.to_string())
    .bind(body.last_name.to_string())
    .fetch_one(&state.db)
    .await
    {
        Ok(users) => HttpResponse::Ok().json(users),
        Err(_) => HttpResponse::InternalServerError().json("Error to create a new user"),
    }
}

#[get("/users/{id}/articles")]
async fn fetch_user_articles(path: Path<i32>, state: Data<AppState>) -> impl Responder {
    let id: i32 = path.into_inner();

    match sqlx::query_as::<_, Article>(
        "SELECT id, title, content, created_by WHERE created_by = $1",
    )
    .bind(id)
    .fetch_all(&state.db)
    .await
    {
        Ok(articles) => HttpResponse::Ok().json(articles),
        Err(_) => HttpResponse::NotFound().json("No articles found"),
    }
}

#[post("/users/{id}/articles")]
async fn create_user_article(
    path: Path<i32>,
    body: Json<CreateArticleBody>,
    state: Data<AppState>,
) -> impl Responder {
    let id: i32 = path.into_inner();

    match sqlx::query_as::<_, Article>("INSERT INTO articles (title, content, created_by) VALUES ($1, $2, $3) RETURNING id, title, content, created_by")
        .bind(body.title.to_string())
        .bind(body.content.to_string())
        .bind(id)
        .fetch_one(&state.db)
        .await
    {
        Ok(article) => HttpResponse::Ok().json(article),
        Err(_) => HttpResponse::InternalServerError().json("Failed to create user article")
    }
}
```

Una vez tengamos esto, tenemos que darle las tablas a nuestra base de datos, esto lo hacemos creando las migraciones:

```bash
sqlx migrate add create_users_table
sqlx migrate add create_articles_table
```

Dentro de los archivos `.sql` que se nos generarón pondremos el código `sql` para crear nuestras tablas.

```sql
-- migrations/create_users_table.sql
CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  last_name TEXT NOT NULL
)
```

```sql
-- migrations/create_articles_table.sql
CREATE TABLE articles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  content TEXT NOT NULL,
  created_by INTEGER,
  FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE
)
```

Luego de ya tener nuestras migraciones listas, hay que ejecutarlas:

```bash
sqlx migrate run
```

Ahora si podemos usar nuestro HttpCient para empezar a probar nuestra API.

## Seguridad en API

```bash
cargo add actix-web
```

### Basic Auth

> [!WARNING]
> Esta forma de autenticar, no es recomendada para producción.

```bash
cargo add actix-web-httpauth
```

Creamos una estructura básica para la API con 2 rutas:

```rust
use actix_web::{get, App, Error, HttpResponse, HttpServer};

#[get("/publico")]
async fn publico() -> HttpResponse {
    HttpResponse::Ok().body("Info publica")
}

#[get("/privado")]
async fn privada() -> HttpResponse {
    HttpResponse::Ok().body("Info privada")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| App::new().service(publico).service(privada))
        .bind(("127.0.0.1", 8080))?
        .run()
        .await
}
```

Si hacemos una consulta a nuestra ruta `/privada` cuando no queremos esto, asi que tenemos que añadir lo siguiente:

```rust
// agregamos estas importaciones
use actix_web_httpauth::{
    extractors::{
        basic::{self, BasicAuth},
        AuthenticationError,
    },
    headers::www_authenticate,
};
```

Ahora a nuestra función `main()` agregamos un `.app_data()`

```rust
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            // Aqui definimos AppData
            .app_data(basic::Config::default().realm("privado"))
            .service(publico)
            .service(privada)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
```

Ahora tenemos que modificar la función `privaeda()` que es a la queremos quitarle el acceso "publico"

```rust
#[get("/privado")]
// Agregamos auth: BasicAuth a los parametros de nuestra func
//                  Regresamos un resultado HttpResponse o Error
async fn privada(auth: BasicAuth) -> Result<HttpResponse, Error> {
    Ok(HttpResponse::Ok().body("Info privada"))
}

```

Pero lo que tenemos actualmente acepta cualquier nombre y contraseña no ninguno en especifico, si queremos eso, tenemos que hacer lo siguiente.

```rust
#[get("/privado")]
async fn privada(auth: BasicAuth) -> Result<HttpResponse, Error> {
    // accedemos al usuario/constraseña y los comparamos con algun valor
    if auth.user_id() == "Wilovy" && auth.password().unwrap() == "Test12345." {
        Ok(HttpResponse::Ok().body("Info privada"))
    } else {
        // Basic Auth te limita a solo regresar errores 401
        Err(AuthenticationError::new(www_authenticate::basic::Basic::default()).into())
    }
}
```

Pero que pasa si tenemos más de 1 endpoint que queremos proteger? no es muy viable tener que estar poniendo `if/else` en cada ruta que queremos protejer:

```rust
if auth.user_id() == "Wilovy" && auth.password().unwrap() == "Test12345." {
    Ok(HttpResponse::Ok().body("Info privada"))
} else {
    Err(AuthenticationError::new(www_authenticate::basic::Basic::default()).into())
}
```

Para facilitarnos estas protecciones multiples crearemos un `middleware`.

Con actix-web podemos crear middlewares desde 0, sin embargo con `actix-httpauth` ya nos da unos middlewares hechos.

```rust
use actix_web::{dev::ServiceRequest, get, App, Error, HttpResponse, HttpServer};
use actix_web_httpauth::middleware::HttpAuthentication;
```

Ahora creamos nuestra función que actuara como middleware

```rust
async fn validador(
    req: ServiceRequest,
    auth: BasicAuth,
) -> Result<ServiceRequest, (Error, ServiceRequest)> {
    if auth.user_id() == "Wilovy" && auth.password().unwrap() == "Test12345." {
        Ok(req)
    } else {
        Err((
            AuthenticationError::new(www_authenticate::basic::Basic::default()).into(),
            req,
        ))
    }
}
```

Ahora en nuestra función registramos nuestro validador:

```rust
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        // Creamos una variable que funcionara como middleware
        let auth = HttpAuthentication::basic(validador);
        App::new()
            .app_data(basic::Config::default().realm("privado"))
            // Le pasamos el middleware a la app
            .wrap(auth)
            .service(publico)
            .service(privada)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
```

Creamos y servimos una nueva ruta:

```rust
#[get("/confidencial")]
async fn confidencial() -> Result<HttpResponse, Error> {
    Ok(HttpResponse::Ok().body("Info confidencial"))
}
```

Ahora si nos fijamos, todas nuestras rutas necesitan la verificación, incluyendo nuestra ruta `/publico` cuando no queremos que esto sea asi, ya que nuestra ruta publica deberia ser publica sin la necesidad de un inicio de sesión (basic auth).

Para lograr esto.

1. Importamos `web`

```rust
use actix_web::{dev::ServiceRequest, get, web, /* ... */}
```

2. Agregamos un `scope` y le añadimos el middleware

```rust
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        let auth = HttpAuthentication::basic(validador);
        App::new()
            // Creamos un servicio
            .service(
                // Creamos un scope con el prefijo `/admin`
                web::scope("/admin")
                    // Montamos el middleware
                    .wrap(auth)
                    // Servimos nuestras rutas
                    // `/admin/privada`
                    .service(privada)
                    // `/admin/confidencial`
                    .service(confidencial),
            )
            .app_data(basic::Config::default().realm("privado"))
            // Dejamos la ruta `/publico` feura del scope para que no tenga el middleware
            .service(publico)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
```

### JWT

#### Instalación y configuracin

Para poder trabajar con `JWT` tenemos que instalar un paquete adicional llamado `jsonwebtoken` y este nos facilita la cración de los `JWT`

```bash
cargo add jsonwebtoken actix-web actix-web-httpauth chrono dotenv
cargo add serde --features=derive
```

Ahora en nuestro `main.rs` vamos a importar lo siguiente:

```rust
use chrono::{Duration, Utc};
use dotenv::dotenv;
use jsonwebtoken::{decode, encode, Algorithm, EncodingKey, Header, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::env;
```

Ahora haremos una función para generar nuestros `JWT`, para esto debemos de tomar en cuenta de `Claims` queremos que tenga nuestro `JWT`, estos [Claims](https://datatracker.ietf.org/doc/html/rfc7519) los podemos ver en la documentación de `JWT` y en el apartado `4.0 JWT Claims` encontraremos un listado de los `Claims` disponibles (tambien podemos agregar los nuestros propios).

Pero aqui te dire una definición corta para cada uno:

- `iss`: Issuer
- `sub`: Subject
- `aud`: Audience
- `exp`: Expiration time (es el unico que es obligatorio desde el paquete (crate) de JWT, no desde la especificación de JWT)
- `nbf`: Not Before
- `iat`: Issued At
- `jti`: JWT Id

Ahora creamos la función con los siguientes claims: `iss`: String, `sub`: String, `exp`: usize y `user_id`: usize

```rust
fn generar_token(iss: String, sub: String, duracion_en_minutos: i64, user_id: usize) -> String {
}
```

Ahora los claims los podemos definir en una `struct`

```rust
#[derive(Serialize, Deserialize, Debug)]
struct Claims {
    iss: String,
    sub: String,
    exp: usize,
    iat: usize,
    user_id: usize,
}
```

Ahora crearemos una función que nos devuelva el valor de nuestro `secret_key`

```rust
fn get_secret_key() -> String {
    dotenv().ok();
    let secret_key = env::var("SECRET_KEY").expect("SECRET_KEY must be set");
    secret_key
}
```

Ahora si podemos trabajar en nuestra función `genrar_token`

```rust
fn generar_token(iss: String, sub: String, duracion_en_minutos: i64, user_id: usize) -> String {
    let header = Header::new(Algorithm::HS512);
    let encoding_key = EncodingKey::from_secret(get_secret_key().as_bytes());

    let exp = (Utc::now() + Duration::minutes(duracion_en_minutos)).timestamp() as usize;
    let iat = Utc::now().timestamp() as usize;

    let my_claims = Claims {
        iss,
        sub,
        exp,
        iat,
        user_id,
    };

    encode(&header, &my_claims, &encoding_key).unwrap()
}
```

Ahora en nuestra función `main`

```rust
fn main() {
    let iss = "Rust JWT".to_owned();
    let sub = "Prueba".to_owned();
    let duracion_en_minutos: i64 = 5;
    let user_id = 1;

    let token = generar_token(iss, sub, duracion_en_minutos, user_id);
    println!("Token: {}", token);
}
```

Ahora ejecutamos el programa

```bash
cargo run
```

Con el token que nos genera, podemos pasarlo por la web de [JWT](https://jwt.io/) y verificar si es correcto.

![Decode JWT](/actix/jwt_io.png)

Ahora, podemos ver que esta web pude desencriptar nuestro JWT, pero necesitamos crear una función para saber si es valido o no.

```rust
fn validar_token(token: String) -> Result<Claims, jsonwebtoken::errors::Error> {
    let validacion = Validation::new(Algorithm::HS512);
    let decoding_key = DecodingKey::from_secret(get_secret_key().as_bytes());

    let resultado = decode::<Claims>(&token, &decoding_key, &validacion);
    match resultado {
        Ok(c) => {
            println!("Token es valido");
            Ok(c.claims)
        }
        Err(e) => {
            println!("Token es invalido");
            Err(e)
        }
    }
}
```

Ahora en nuestra función `main`:

```rust
fn main() {
    let iss = "Rust JWT".to_owned();
    let sub = "Prueba".to_owned();
    let duracion_en_minutos: i64 = 5;
    let user_id = 1;

    let token = generar_token(iss, sub, duracion_en_minutos, user_id);
    let resultado = validar_token(token);
    match resultado {
        Ok(claims) => println!("Los Claims son: {:?}", claims),
        Err(e) => println!("El token es invalido: {:?}", e),
    }
}
```

Esto nos tiene que devolver la forma desencriptada de nuestro token, si es que es exitoso.

#### Protegiendo endpoints con JWT

Continuando con nuestro código anterior, vamos a agregar las importaciones necesarias para trabajar con `Actix`

```rust
use actix_web::{dev::ServiceRequest, error, get, post, web, App, Error, HttpResponse, HttpServer};
```

Ahora convertimos nuestra función `main` en asincrona

```rust
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // code ....
}
```

Ahora, creremos una `struct` para simular el login form de nuestra app

```rust
#[derive(Serialize, Deserialize)]
struct LoginForm {
    usuario: String,
    password: String
}
```

Tambien si el login es valido vamos a retornar un `login result`

```rust
#[derive(Serialize, Deserialize)]
struct LoginResult {
    token: String,
}
```

Ahora vamos a crear un `endpoint` de tipo `post`

```rust
#[get("/login")]
async fn login(form: web::Form<LoginForm>) -> HttpResponse {
    if form.usuario == "Wilovy" && form.password == "Test12345." {
        let iss = "Rust JWT".to_owned();
        let sub = "Prueba".to_owned();
        let duracion_en_minutos: i64 = 5;
        let user_id = 1;
        let token = generar_token(iss, sub, duracion_en_minutos, user_id);
        let respuesta = LoginResult { token };
        HttpResponse::Ok().json(respuesta)
    } else {
        HttpResponse::Unauthorized().body("Login invalido")
    }
}
```

Ahora vamos a probarlo, tenemos que levantar nuestro servidor en nuestra función `main`

```rust
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| App::new().service(login))
        .bind(("127.0.0.1", 8080))?
        .run()
        .await
}
```

Ahora si podemos probar nuestra ruta usando un `Form URL Encoded` y si todo sale bien nos deberia regresar algo como:

![Login](/actix/login.png)

Y si las credenciales son incorrectas nos aparecera algo como:

![LoginErr](/actix/login_err.png)

Ahora si, creemos una nueva ruta para protejerla con `JWT`

```rust
#[get("/privado")]
async fn privado() -> HttpResponse {
    HttpResponse::Ok().body("Privado")
}
```

Ahora servimos nuestra nueva ruta dentro de nuestra app en un `scope`

```rust
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .service(web::scope("/admin").service(privado))
            .service(login)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
```

Ahora si intentamos acceder a la ruta `/admin/privado`, lo podremos hacer ya que aun no hacemos ningún middleware para protejerla.

Antes de eso, tenemos que agregar el import necesario

```rust
use actix_web_httpauth::{extractors::bearer::BearerAuth, middleware::HttpAuthentication};
```

Y ahora si podemos hacer un validador

```rust
async fn validador(
    req: ServiceRequest,
    credenciales: Option<BearerAuth>,
) -> Result<ServiceRequest, (Error, ServiceRequest)> {

    let Some(credenciales) = credenciales else {
        return Err((error::ErrorBadRequest("No se especifico el token"), req));
    };

    let token = credenciales.token();
    let resultado = validar_token(token.to_owned());
    match resultado {
        Ok(_) => Ok(req),
        Err(_) => Err((error::ErrorForbidden("No tiene acceso"), req)),
    }
}
```

Ahora implementamos el validador en nuestro scope donde esta la ruta que queremos proteger

```rust
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        let auth = HttpAuthentication::with_fn(validador);

        App::new()
            .service(web::scope("/admin").wrap(auth).service(privado))
            .service(login)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
```

Ahora si iniciamos sesion en nuestro endpoint de `/login`

![Login](/actix/login_bearer.png)

Copiamos el token que nos arroja y nos vamos a nuestra ruta `/admin/privado` y si es existoso:

![Privado](/actix/bearer_privado.png)

Si no lo es seria algo como:

![Privado err](/actix/bearer_error.png)

#### Implementación de Refresh token

Siguendo el contenido anterior, responderemos la duda de ¿como refrescar un JWT? ya que esto es util para no tener que estarle pidiendo al usuario que vuelva a hacer login cada que se expire el token.

> [!NOTE]
> Continuaremos con el código anterior.

Lo que teniamos hasta este momento es que al momento de que un usuario hace login, se le regrese un `token` en base a la `struct` que llamamos `LoginResult`, modificaremos esta `struct` para que nos regrese un `refresh`

```rust
#[derive(Serialize, Deserialize)]
struct LoginResulti {
    token: String,
    refresh: String,
}
```

Tambien modificaremos nuestros `claims` para agregar el refresh.

```rust

struct Claims {
    iss: String,
    sub: String,
    exp: usize,
    iat: usize,
    tipo: String,
    user_id: usize,
}
```

Ahora crearemos un nuevo endpoint para refrescar nuestros tokens, primero debemos crear su `struct`

```rust
#[derive(Serialize, Deserialize)]
struct RefreshResult {
    token: String,
}
```

Ahora hay que modificar la función de `generar_token`

```rust
// Añadimos `tipo: String` como parametro
fn generar_token(iss: String, sub: String, duracion_en_minutos: i64, user_id: usize, tipo: String)

let my_claims = Claims {
    iss,
    sub,
    exp,
    iat,
    tipo, // Y lo pasamos a `my_claims`
    user_id,
};
```

Ahora en el `validador` vamos a dejar que manejar que los tokens que no sean refresh nos permitan validarlo, pero si son refresh, no permitiremos que se valide

```rust
// Solo cambiamos el `match`
match resultado {
    Ok(claims) => {
        if claims.tipo != "refresh" {
            return Ok(req);
        }
        Err((error::ErrorForbidden("No tiene acceso"), req))
    },
    Err(_) => Err((error::ErrorForbidden("No tiene acceso"), req)),
}
```

Ahora en nuestra función `main` vamos a modificar algunas cosas ya que dan errores.

1. Pasaremos el nuevo parametro que definimos

```rust
let token = generar_token(
    iss.clone(),
    sub.clone(),
    duracion_en_minutos,
    user_id,
    "token-normal".to_owned(),
);
```

2. Tambien hay que definir una variable para la duración de el tiempo de vida de nuestro token `refresh`

```rust
let duracion_dia: i64 = 1440;
```

3. Hay que definir el token `refresh`

```rust
let refresh = generar_token(
    iss.clone(),
    sub.clone(),
    duracion_dia,
    user_id,
    "refresh".to_owned(),
);
```

4. Pasamos el `refresh` en la respuesta

```rust
let respuesta = LoginResult { token, refresh };
```

Entonces el `token-normal` va a durar 5min y el `token-refresh` va a durar 1 dia, ahora hay que implementar toda la lógica de refrescamiento, ahora si creamos nuestro endpoint.

```rust
#[post("/refresh-token")]
async fn refresh_token(refresh_jwt: Option<BearerAuth>) -> HttpResponse {
    let Some(refresh_jwt) = refresh_jwt else {
        return HttpResponse::Forbidden().body("Token no enviado");
    };

    let claims = validar_token(refresh_jwt.token().to_owned());

    match claims {
        Ok(c) => {
            // Crear el nuevo token-normal
            if c.tipo == "refresh" {
                let iss = c.iss.to_owned();
                let sub = c.sub.to_owned();
                let duracion_en_minutos = 5;
                let tipo = "token-normal".to_owned();
                let user_id = c.user_id;

                let token = generar_token(iss, sub, duracion_en_minutos, user_id, tipo);
                let resultado: RefreshResult = RefreshResult { token };

                HttpResponse::Ok().json(resultado)
            } else {
                HttpResponse::Unauthorized().body("")
            }
        }
        Err(_) => HttpResponse::Unauthorized().body(""),
    }
}
```

Ahora incluimos nuestra nueva ruta a nuestra app:

```rust
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        let auth = HttpAuthentication::with_fn(validador);

        App::new()
            .service(web::scope("/admin").wrap(auth).service(privado))
            .service(login)
            .service(refresh_token) // Fuera del scope `/admin`
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
```

Actualizamos nuestros imports

```rust
use actix_web_httpauth::{
    extractors::bearer::{BearerAuth, Config as BearerConfig},
    middleware::HttpAuthentication,
};
```

Ahora agregamos este `BearerConfig` a nuestro servidor

```rust
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        let auth = HttpAuthentication::with_fn(validador);

        App::new()
            // Hacemos que sea la config por defecto
            .app_data(BearerConfig::default().realm("jwt"))
            .service(web::scope("/admin").wrap(auth).service(privado))
            .service(login)
            .service(refresh_token)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
```

Corremos nuestro servidor y nos vamos a `Insomnia` para empezar a hacer pruebas.

Aqui vemos que ahora cuando hacemos `login` nos regresa 2 tokens. El `token` y el `refresh`, para nuestros endpoints normales siempre usaremos el `token`.

![Login refresh](/actix/login_refresh.png)

Ahora si intentamos refrescar un token viejo con el token `refresh`

![Refresh token](/actix/refresh_token.png)

Ejemplo de un token viejo:

![Token viejo](/actix/token_viejo.png)

Y si ahora poner el token nuevo generado con el `refresh`

![New Token](/actix/token_nuevo.png)

#### Roles en APIs

Otra duda que esta pendiente es como implementar Roles en una API, para esto usaremos un crate/paquete llamado `actix-web-grants`.

> [!NOTE] > `actix-web-grants` no necesita `actix-web-httpauth` para funcionar y pero se integran muy bien juntos.

Seguiremos trabajando con el código que ya tenemos hasta el momento.

Importamos:

```rust
use actix_web_grants::authorities::AttachAuthorities;
use actix_web_grants::protect;
```

Ahora creamos un nuevo endpoint

```rust
#[get("/solo-director")]
#[protect("DIRECTOR")]
async fn solo_director() -> HttpResponse {
    HttpResponse::Ok().body("Información solo para directores")
}

// Y lo servimos en nuestro `scope` donde usamos el JWT
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        let auth = HttpAuthentication::with_fn(validador);

        App::new()
            .app_data(BearerConfig::default().realm("jwt"))
            .service(
                web::scope("/admin")
                    .wrap(auth)
                    .service(privado)
                    // Aqui es donde lo servimos
                    .service(solo_director),
            )
            .service(login)
            .service(refresh_token)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
```

`actix-web-grants` le da un nuevo metodo enfocado a roles al `ServiceRequest`.

Ahora modificamos nuestra función `validador` ya que esta es la que esta actuando como middleware.

```rust
async fn validador(
    req: ServiceRequest,
    credenciales: Option<BearerAuth>,
) -> Result<ServiceRequest, (Error, ServiceRequest)> {
    let Some(credenciales) = credenciales else {
        return Err((error::ErrorBadRequest("No se especifico el token"), req));
    };

    let token = credenciales.token();
    let resultado = validar_token(token.to_owned());
    match resultado {
        Ok(claims) => {
            if claims.tipo != "refresh" {
                // En este caso usamos el user_id para asignarle un rol
                if claims.user_id == 1 {
                    req.attach(vec!["DIRECTOR".to_string()]);
                }
                if claims.user_id == 2 {
                    req.attach(vec!["GERENTE".to_string()]);
                }
                return Ok(req);
            }
            Err((error::ErrorForbidden("No tiene acceso"), req))
        }
        Err(_) => Err((error::ErrorForbidden("No tiene acceso"), req)),
    }
}
```

Ahora lanzamos nuestro serviodor.

1. Hacemos login.
2. Verificamos con nuestra ruta `/admin/privado` que realmente tengamos acceso con nuestro `token`.
3. Ahora vayamos a nuestro nuevo endpoint `/admin/solo-directores`.

![Directores](/actix/directores.png)

Recordemos que este endpoint solo esta disponible para directores, y nosotros definimos que los usuarios con id 1 son directores. (Es el caso de nuestra cuenta recien creada con el login)

Ahora cambiemos este campo a id 2 en nuestro endpoint `/login`

```rust

#[post("/login")]
async fn login(form: web::Form<LoginForm>) -> HttpResponse {
    if form.usuario == "Wilovy" && form.password == "Test12345." {
        let iss = "Rust JWT".to_owned();
        let sub = "Prueba".to_owned();
        let duracion_en_minutos: i64 = 5;
        let duracion_dia: i64 = 1440;
        // Aqui cambiamos el id
        let user_id = 2;
        let token = generar_token(
            iss.clone(),
            sub.clone(),
            duracion_en_minutos,
            user_id,
            "token-normal".to_owned(),
        );
        let refresh = generar_token(
            iss.clone(),
            sub.clone(),
            duracion_dia,
            user_id,
            "refresh".to_owned(),
        );

        let respuesta = LoginResult { token, refresh };
        HttpResponse::Ok().json(respuesta)
    } else {
        HttpResponse::Unauthorized().body("Login invalido")
    }
}
```

Volvemos a hacer un login otra vez y repetimos los pasos anteriores enumerados.

![GERENTES](/actix/gerentes.png)

Como podemos ver, como nosotros definimos que los usuarios con id 2 son `gerentes` pero nuestro endpoint `/admin/solo-director` tiene el macro `#[protect("DIRECTOR")]` no nos da el acceso a este endpoint.

Pero, y si ahora queremos tener un endpoint que tenga más de un rol de acceso a nuestro endpoint, creemos uno nuevo.

```rust
#[get("/solo-supervisores")]
#[protect(any("DIRECTOR", "GERENTE"))]
async fn solo_supervisores() -> HttpResponse {
    HttpResponse::Ok().body("Información solo para supervisores")
}
// Y lo servimos
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        let auth = HttpAuthentication::with_fn(validador);

        App::new()
            .app_data(BearerConfig::default().realm("jwt"))
            .service(
                web::scope("/admin")
                    .wrap(auth)
                    .service(privado)
                    .service(solo_director)
                    // Aqui lo servimos
                    .service(solo_supervisores)
            )
            .service(login)
            .service(refresh_token)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
```

Ahora si probemos nuestro nuevo endpoint.

1. Hacemos login
2. Probamos nuestro `token` en el endpoint `/admin/solo-director` y nos deberia dar error ya que tenemos el rol `GERENTE`
3. Ahora probamos en el nuevo endpoint `/admin/solo-supervisores` y deberiamos tener acceso.

![Supervisores](/actix/supervisores.png)

> [!NOTE]
> Podemos cambiar el `user_id` a 1 para que nos de el rol `DIRECTOR` y chequear el endpoint nuevo.

#### Implementa control de permisos en APIs

> [!NOTE]
> Seguiremos con el código que tenemos hasta ahorita.

Crearemos un nuevo endpoint solo para que el usuario logeado pueda ver su info personal y la servimos.

```rust
#[get("/inforamcion-personal/{user_id}")]
#[protect("LOG_IN")]
async fn info_personal(path_param: web::Path<usize>, credenciales: Option<BearerAuth>) -> HttpResponse {
    HttpResponse::Ok().body("Tu info personal")
}
```

Ahora en nuestro `middleware` (`fn validador`)

```rust
async fn validador(
    req: ServiceRequest,
    credenciales: Option<BearerAuth>,
) -> Result<ServiceRequest, (Error, ServiceRequest)> {
    let Some(credenciales) = credenciales else {
        return Err((error::ErrorBadRequest("No se especifico el token"), req));
    };

    let token = credenciales.token();
    let resultado = validar_token(token.to_owned());
    match resultado {
        Ok(claims) => {
            if claims.tipo != "refresh" {
                if claims.user_id == 1 {
                    // Les pasamos un nuevo `rol` llamado `LOG_IN`
                    req.attach(vec!["DIRECTOR".to_string(), "LOG_IN".to_string()]);
                }
                if claims.user_id == 2 {
                    req.attach(vec!["GERENTE".to_string(), "LOG_IN".to_string()]);
                }
                return Ok(req);
            }
            Err((error::ErrorForbidden("No tiene acceso"), req))
        }
        Err(_) => Err((error::ErrorForbidden("No tiene acceso"), req)),
    }
}
```

Ahora lo que tenemos que hacer es que cuando se ingrese a la ruta `/información-personal` el usuario con id 1 solo pueda ver la información personal del usuario con id 1.

Para lograr esto en el macro `protect` podemos pasar un parametro mas llamado `expr` que hace referencia a expresión.

Este parametro tiene que devolver un booleano, si se cumple el rol y el `expr` deja acceder a la ruta, si no, la bloquea.

`EXPR` admite:

- Comparaciónes en linea: `1 == 1`
- Funciones que regresaen booleanos

Entonces con esta info nueva crearemos una función nueva para comparar el id del path param y el id de las credenciales.

```rust
fn id_igual_claim(path_param: web::Path<usize>, credenciales: Option<BearerAuth>) -> bool {
    let Some(credenciales) = credenciales else {
        return false;
    };
    let user_id = path_param.into_inner();
    let token = credenciales.token();
    let resultado = validar_token(token.to_owned());
    match resultado {
        Ok(claims) => claims.user_id == user_id,
        Err(_) => false,
    }
}
```

Y ahora haremos que nuestro endpoint reciba este `expr`

```rust
#[get("/inforamcion-personal/{user_id}")]
#[protect("LOG_IN", expr = "id_igual_claim(path_param, credenciales)")]
async fn info_personal(
    path_param: web::Path<usize>,
    credenciales: Option<BearerAuth>,
) -> HttpResponse {
    HttpResponse::Ok().body("Tu info personal")
}
```

Ahora podemos probar nuestro nuevo endpoint.

![Permiso valido](/actix/valido_permiso.png)

Y ahora si pasamos un path param que no es nuestro id

![Error permiso](/actix/error_permiso.png)

## CORS

```bash
cargo add actix-cors
```

> [!NOTE]
> Código sacado de la documentación [actix-cors](https://github.com/actix/actix-extras/tree/master/actix-cors)

```rust
use actix_cors::Cors;
use actix_web::{http::header, middleware::Logger, web, App, HttpServer};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    log::info!("starting HTTP server at http://localhost:8080");

    HttpServer::new(move || {
        App::new()
            // `permissive` is a wide-open development config
            // .wrap(Cors::permissive())
            .wrap(
                // default settings are overly restrictive to reduce chance of
                // misconfiguration leading to security concerns
                Cors::default()
                    // add specific origin to allowed origin list
                    .allowed_origin("http://project.local:8080")
                    // allow any port on localhost
                    .allowed_origin_fn(|origin, _req_head| {
                        origin.as_bytes().starts_with(b"http://localhost")
                        // or
                        // origin.as_bytes().ends_with(b".rust-lang.org")

                        // manual alternative:
                        // unwrapping is acceptable on the origin header since this function is
                        // only called when it exists
                        // req_head
                        //     .headers()
                        //     .get(header::ORIGIN)
                        //     .unwrap()
                        //     .as_bytes()
                        //     .starts_with(b"http://localhost")
                    })
                    // set allowed methods list
                    .allowed_methods(vec!["GET", "POST"])
                    // set allowed request header list
                    .allowed_headers(&[header::AUTHORIZATION, header::ACCEPT])
                    // add header to allowed list
                    .allowed_header(header::CONTENT_TYPE)
                    // set list of headers that are safe to expose
                    .expose_headers(&[header::CONTENT_DISPOSITION])
                    // allow cURL/HTTPie from working without providing Origin headers
                    .block_on_origin_mismatch(false)
                    // set preflight cache TTL
                    .max_age(3600),
            )
            .wrap(Logger::default())
            .default_service(web::to(|| async { "Hello, cross-origin world!" }))
    })
    .workers(1)
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
```

> [!NOTE] > [Aqui hay otro ejemplo de CORS en Actix](https://crates.io/crates/actix-cors)

## LOGS

Los logs son una parte muy importante para nuestra aplicación web ya que estos nos ofrecen información de que esta ocurriendo con nuestra app.

Para poder integrar esto con nuestra API debemos instalar 2 crates

- [tracing](https://crates.io/crates/tracing)
- [tracing-subscriber](https://crates.io/crates/tracing-subscriber)

Esto lo logramos haciendolo de la siguiente forma:

```bash
cargo add tracing
cargo add tracing-subscriber -F env-filter
```

```rust
// Importamos el middleware Logger que actix nos da
use actix_web::{get, middleware::Logger, web, App, HttpResponse, HttpServer};
use serde::Serialize;

// Importamos lo que necesitamos de tracing y tracing_subscriber
use tracing::info;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[derive(Serialize)]
struct Message {
    message: String,
}

#[get("/")]
async fn hc() -> HttpResponse {
    // Mandamos un log
    info!("Received request to /");

    HttpResponse::Ok().json(Message {
        message: "Ok!".to_string(),
    })
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Iniciamos el subscriber
    tracing_subscriber::registry()
        .with(EnvFilter::from_default_env().add_directive("info".parse().unwrap()))
        .with(fmt::layer().compact())
        .init();

    let host = "0.0.0.0";
    let port = 8080;

    HttpServer::new(|| App::new()
        // Wrapeamos el logger a nuestra api
        .wrap(Logger::default())
            // Servimos nuestras rutas
            .service(hc)
        )
        .bind((host, port))?
        .run()
        .await
}
```

Ejemplo de los logs que hemos generado:

```bash
2025-01-05T09:26:51.064157Z  INFO actix_server::builder: starting 4 workers
2025-01-05T09:26:51.064357Z  INFO actix_server::server: Actix runtime found; starting in Actix runtime
2025-01-05T09:26:51.064463Z  INFO actix_server::server: starting service: "actix-web-service-0.0.0.0:8080", workers: 4, listening on: 0.0.0.0:8080
2025-01-05T09:26:51.291252Z  INFO DockerAPI: Received request to /
2025-01-05T09:26:51.291496Z  INFO actix_web::middleware::logger: 127.0.0.1 "GET / HTTP/1.1" 200 17 "-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36" 0.000433
```

---

[Playlist de donde se saco la mayoria de la info de estas notas](https://www.youtube.com/playlist?list=PLysg0qAvNg48YN4R-MZo3pXsuUjtAtPTV)

