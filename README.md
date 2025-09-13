# Autenticación Segura (Express + JWT + CSRF)

Aplicación de ejemplo con Express que muestra buenas prácticas de autenticación:

- Bcrypt para hashear contraseñas
- Sesiones de Express y JWT en cookie `HttpOnly`
- Protección CSRF con `csurf` y cabeceras de seguridad con `helmet`
- Validaciones con `express-validator`
- SQLite (better-sqlite3) como persistencia
- Bloqueo de cuenta por intentos fallidos

## Requisitos

- Node.js 18+ (recomendado)

## Instalación

1) Instalar dependencias:

```
npm install
```

2) Configurar variables básicas en `config.js`:

- `PORT`: puerto donde corre el servidor (por defecto 3000)
- `SECRET_KEY`: clave secreta para firmar JWT y la sesión 

Archivo: `config.js`

```

```

3) Base de datos (SQLite)

- El archivo se llama `data.db`. Se inicializa al levantar la app a través de `init_db.js`.
- Esquema mínimo esperado por la app:

```
users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL,
  password TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user'
)
```

## Ejecutar en desarrollo

```
npm run dev
```

Abrí: http://localhost:3000

## Rutas principales

- `GET /`: página con formularios de registro y login, estado de sesión/JWT y enlaces a zonas protegidas. Render EJS.
- `POST /register`: registra usuario (`email`, `password`). Valida formato, hashea con bcrypt y crea el usuario con rol `user`.
- `POST /login`: login con bloqueo por intentos fallidos. Crea sesión y setea cookie `HttpOnly` con JWT.
- `POST /logout`: elimina cookie del JWT y destruye la sesión.
- `GET /protected`: requiere JWT válido (middleware `auth`).
- `GET /admin`: requiere rol `admin` (middleware `requireRole('admin')`).
- `POST /admin/promote`: requiere rol `admin`. Promueve a `admin` por `email`.

Importante: los `POST` requieren token CSRF. Los templates EJS ya incluyen `name="_csrf"`.

## Seguridad aplicada

- `helmet`: cabeceras seguras (CSP desactivado por simplicidad en dev)
- `csurf`: protección CSRF basada en sesión
- Cookies `HttpOnly` + `sameSite='lax'` para JWT y sesión
- JWT con expiración de 1h
- Validación de inputs con `express-validator`
- Hasheo de contraseñas con `bcrypt`
- Bloqueo temporal tras varios intentos fallidos de login

## Roles y administración

- Para acceder a `/admin` necesitás un usuario con `role='admin'`.
- Cómo crear el primer admin (si no tenés acceso a `/admin` aún):

```
sqlite3 data.db "UPDATE users SET role='admin' WHERE email='tu@correo.com';"
```

Luego ingresá con ese usuario y podrás promover otros desde `/admin`.

## Estructura del proyecto

- `index.js`: servidor Express, rutas, middlewares y vistas (EJS)
- `utils.js`: helpers de validación, hashing y middleware `auth` (JWT)
- `models/consultas.js`: accesos a base (insert/select/update)
- `init_db.js`: inicialización de SQLite
- `views/*.ejs`: vistas EJS (home, protegida, admin)
- `config.js`: puerto y secret key

## Troubleshooting

- `EBADCSRFTOKEN`: refrescá la página para obtener un nuevo token CSRF.
- JWT inválido/expirado: iniciá sesión nuevamente.
- No puedo promover a admin: asegurate de tener la columna `role` y de acceder con un usuario que ya sea `admin` (o setealo manualmente como se explica arriba).

## Licencia

ISC (ver `package.json`).
