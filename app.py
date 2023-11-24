from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

app = Flask(__name__)

# Configuración de Flask-JWT-Extended
app.config['JWT_SECRET_KEY'] = 'clave_secreta'  # Aqui iria mi clave
jwt = JWTManager(app)

# "Base de datos" simulada de usuarios
usuarios = {
    'usuario1': {
        'username': 'jose luis minota',
        'password': '123456'
    },
    'usuario2': {
        'username': 'nuevo usuario',
        'password': '159753'
    }
}

# Ruta para el inicio de sesión
@app.route('/login', methods=['POST']) # Se crea una ruta login con el metodo post para poder enviar los datos del usuario solo si son validos o no.
def login():
    if not request.is_json: # Se solicitan los datos del formulario, en este caso no existen, por lo tanto genera un error.
        return jsonify({"mensaje": "Falta el cuerpo JSON"}), 400

    # En este punto sí existen los datos entonces asigna en variables los valores, y en el caso de que no exista se asigna el valor none... Los datos deben venir de un formulario.
    username = request.json.get('username', None) #Metodo get para traer el username.
    password = request.json.get('password', None) #Metodo get para traer el password.

    if not username or not password:  #Condicional para validar si existe o no el usuario o la contraseña
        return jsonify({"mensaje": "Usuario o contraseña faltante"}), 400

    if username not in usuarios or usuarios[username]['password'] != password:
        return jsonify({"mensaje": "Credenciales incorrectas"}), 401 # Condicional para validar que el usuario exista dentro de la "base de datos".

    # Crear token de acceso usando Flask-JWT-Extended
    access_token = create_access_token(identity=username)
    return jsonify(access_token=access_token), 200

# Ruta protegida que requiere un token válido
@app.route('/protegido', methods=['GET'])
@jwt_required()
def protegido():
    # Obtener la identidad del token actualmente en uso
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200

if __name__ == '__main__':
    app.run(debug=True)
