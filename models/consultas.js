import {db} from '../init_db.js';


function agregar_user(email,h_password,role) {
    const nuevoUser = db.prepare("INSERT INTO users (email, password, role) VALUES (?,?,?)").run(email,h_password.trim(),role);
    const id_nuevo = nuevoUser.lastInsertRowid;
    const user_agregado = obtener_user(email);
    return user_agregado
}

function obtener_user(email) {
    return db.prepare("SELECT * FROM users WHERE email = ? ").get(email)
}



function set_role(email){
    return db.prepare(`UPDATE users SET role = 'admin' WHERE email = ?`).run(email)
}

export {
    agregar_user,
    obtener_user,
    set_role
}