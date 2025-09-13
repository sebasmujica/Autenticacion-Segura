import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import express from 'express';
import {PORT, SECRET_KEY} from './config.js';

const app = express();

app.use(cookieParser());

function username_validation(username){
    if (typeof username !== 'string') throw new Error('username debe ser tipo de dato: string')
    if(username.length < 3) throw new Error('username debe poseer al menos 3 caracteres');
}

function password_validation(password){
    if (typeof password !== 'string') throw new Error('password debe ser tipo de dato: string')
    if(password.length < 6) throw new Error('password debe poseer al menos 6 caracteres');
}

const hashing = (password) => {
    return bcrypt.hashSync(password, 10);
};

const validar_password = (password,h_password) => {
    return bcrypt.compareSync(password, h_password)
};

function auth(req, res, next) {
    const token = req.cookies.access_token;
    if (!token) return res.status(403).send('Acceso no autorizado');
    try {
        req.user = jwt.verify(token, SECRET_KEY);
        next();
    } catch (e) {
        return res.status(401).send('No autorizado');
    }
}



export {
    username_validation,
    password_validation,
    hashing,
    validar_password,
    auth,
}