import express from 'express';
import cookieParser from 'cookie-parser';
import session from 'express-session';
import csrf from 'csurf';
import helmet from 'helmet';
import jwt from 'jsonwebtoken';
import { body, validationResult } from 'express-validator';

import { PORT, SECRET_KEY } from './config.js';
import { username_validation, password_validation, hashing, validar_password, auth } from './utils.js';
import { agregar_user, obtener_user, set_role } from './models/consultas.js';
import './init_db.js';

const isProd = process.env.NODE_ENV === 'production';

const app = express();


// Middlewares base 
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(helmet({ hsts:false, contentSecurityPolicy:false }));


app.use(cookieParser());
// Sesión (cookie con ID de sesión) 
app.use(session({
    secret: SECRET_KEY,
    resave: false,
    saveUninitialized: false,
    cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: false, // en prod con HTTPS
    maxAge: 1000 * 60 * 60, // 1h
}
}));

// CSRF (usa la sesión) 
const csrfProtection = csrf();
app.use(csrfProtection);

// EJS 
app.set('view engine', 'ejs');
app.set('views', './views');

// Intentos de login en memoria 
const loginAttempts = {};
const MAX_ATTEMPTS = 4;
const LOCK_MS = 3 * 60 * 1000; // 3 minutos

// Middleware de rol (sirve con sesión o JWT) 
function requireRole(...roles) {
    return (req, res, next) => {
    const role = req.session?.user?.role || req.user?.role || 'user';
    if (!roles.includes(role)) return res.status(403).send('Prohibido');
    next();
};
}

// Home: muestra formularios + estado de sesión/JWT 
app.get('/', (req, res) => {
    const token = req.cookies?.access_token;
    let email = null;

    if (token) {
        try {
        const data = jwt.verify(token, SECRET_KEY); // { user, role }
        email = data.user;
        } catch { /* token inválido/expirado → email null */ }
    }
    return res.status(200).render('index', { email, msg: null, error: null, csrfToken: req.csrfToken() });
});

// Register 
app.post('/register',body('email').isEmail().normalizeEmail(),body('password').isLength({ min: 8, max: 72 }),(req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).render('index', { email: null, msg: null, error: 'Datos no válidos', csrfToken: req.csrfToken() });
    }

    const { email, password } = req.body;
    const existe = obtener_user(email);
    if (existe) {
        return res.status(409).render('index', { email: null, msg: null, error: 'Usuario ya existe', csrfToken: req.csrfToken() });
    }

    try {
      // validaciones propias 
        username_validation(email);
        password_validation(password);
    } catch {
        return res.status(400).render('index', { email: null, msg: null, error: 'Datos no válidos', csrfToken: req.csrfToken() });
    }

    let hashedPassword;
    try {
      hashedPassword = hashing(password); // bcrypt en tu utils
    } catch {
        return res.status(500).render('index', { email: null, msg: null, error: 'Error de hashing', csrfToken: req.csrfToken() });
    }

    try {
      // insertar con rol por defecto 'user' (asegurate en la DB)
        agregar_user(email, hashedPassword,'user');
      // opcional: iniciar sesión de una
        req.session.user = { email, role: 'user' };
        return res.status(201).render('index', { email: null, msg: 'Usuario creado', error: null, csrfToken: req.csrfToken() });
    } catch {
        return res.status(500).render('index', { email: null, msg: null, error: 'Error agregando user', csrfToken: req.csrfToken() });
    }
}
);

// Login con bloqueo 
app.post('/login',body('email').isEmail().normalizeEmail(),body('password').isLength({ min: 8, max: 72 }),(req, res) => {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
        return res.status(400).render('index', { email: null, msg: null, error: 'Datos no válidos', csrfToken: req.csrfToken() });
    }

    const { email, password } = req.body;

    const now = Date.now();
    if (!loginAttempts[email]) loginAttempts[email] = { count: 0, lockedUntil: 0 };

    if (loginAttempts[email].lockedUntil > now) {
        const min = Math.ceil((loginAttempts[email].lockedUntil - now) / 60000);
        return res.status(423).render('index', { email: null, msg: null, error: `Cuenta bloqueada. Intenta en ${min} min`, csrfToken: req.csrfToken() });
    }

    const user = obtener_user(email); // { email, password(hash), role }
    if (!user) {
        return res.status(404).render('index', { email: null, msg: null, error: 'Usuario no encontrado', csrfToken: req.csrfToken() });
    }

    const ok = validar_password(password, user.password);
    if (!ok) {
        loginAttempts[email].count++;
        if (loginAttempts[email].count >= MAX_ATTEMPTS) {
        loginAttempts[email].lockedUntil = now + LOCK_MS;
        return res.status(423).render('index', { email: null, msg: null, error: 'Cuenta bloqueada por demasiados intentos', csrfToken: req.csrfToken() });
        }
        return res.status(401).render('index', { email: null, msg: null, error: `Password incorrecto. Intentos: ${loginAttempts[email].count}/${MAX_ATTEMPTS}`, csrfToken: req.csrfToken() });
    }

    // éxito → reset intentos
    loginAttempts[email] = { count: 0, lockedUntil: 0 };

    // Se crea la Sesión 
    req.session.user = { email: user.email, role: user.role || 'user' };

    // Se crear el JWT 
    const token = jwt.sign({ user: user.email, role: user.role || 'user' }, SECRET_KEY, { expiresIn: '1h' });
    //Se envia la cookie firmado con el JWT
    res.cookie('access_token', token, {
        httpOnly: true,
        sameSite: 'lax',
        secure: false,
      maxAge: 1000 * 60 * 60
    });

        return res.status(200).render('index', { email, msg: 'Login exitoso', error: null, csrfToken: req.csrfToken() });
    }
);

// Logout 
app.post('/logout', (req, res) => {
    // Elimina la cookie con el JWT
    res.clearCookie('access_token', { sameSite: 'strict', secure: false });
    //Elimina la cookie con la sesion 
    res.clearCookie('connect.sid', { path: '/', sameSite: 'Lax', secure: isProd})
    req.session.destroy(() => {
        return res.redirect("/")
    });
});

// Rutas protegidas 
app.get('/protected', auth, (req, res) => {
  // auth viene de utils.js (JWT). Si preferís por sesión: crea un middleware authSession.
    return res.render('protected', { email: req.user.user });
});

// Solo admin 
app.get('/admin', auth, requireRole('admin'), (req, res) => {
    res.render('admin', { csrfToken: req.csrfToken() });
});

app.post('/admin/promote', auth, requireRole('admin'), (req, res) => {
    const { email } = req.body || {};
    if (!email) return res.status(400).send('Falta email');
    set_role(email, 'admin');
    res.render('promoted', {email,csrfToken : req.csrfToken()})
});

app.use((err,req, res, next) => { 
    if (err.code === "EBADCSRFTOKEN") {
        if (req.accepts("html")) return res.redirect("/"); // o renderizá una página con mensaje
        return res.status(403).json({ error: "CSRF inválido. Recargá la página." });
        }
        next(err);
});

// Start 
app.listen(PORT, () => {
    console.log(`http://localhost:${PORT}`);
});
