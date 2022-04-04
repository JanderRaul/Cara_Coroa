import random
from flask import Flask, render_template, session, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, RadioField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
import firebase_admin
from firebase_admin import credentials
from firebase_admin import db as dbFire

cred = credentials.Certificate("firebase-sdk.json")
firebase_admin.initialize_app(cred, {
    'databaseURL': 'https://appcaracoroa-default-rtdb.firebaseio.com/'
})


app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'ot61vy32PjF%Rw6@$XdX'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
@login_manager.user_loader
def load_user(user_id):
    # return User.query.get(int(user_id))
    return dbFire.reference("User").get()[user_id]

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(20), nullable=False)
    nrJogos = db.Column(db.Integer, nullable=True)
    ganhos = db.Column(db.Integer, nullable=True)

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Escreva seu nick"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Digite sua senha"})
    submit = SubmitField("Registrar")
    def validate_username(self, username):
        # existing_user_name = User.query.filter_by(username=username.data).first()
        existing_user_name = True
        try:
            ref = dbFire.reference("User").get()[username.data]
        except:
            existing_user_name = False
        if existing_user_name:
            raise ValidationError("Este nome já está sendo utilizado. Escolha outro nome!!")

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Escolha seu nick.."})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Crie sua senha.."})
    submit = SubmitField("Login")

class JogarForm(FlaskForm):
    jogar = RadioField(choices=[('0','Cara'), ('1','Coroa')])
    submit = SubmitField("Jogar")

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = dbFire.reference('User').get()[form.username.data]
        if user['senha'] == form.password.data:
            global usuario_atual
            usuario_atual = user['name']
            return redirect(url_for('dashboard'))
    
    return render_template('login.html', form=form)

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    global usuario_atual
    usuario_atual = None
    return redirect(url_for('login'))

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    user = usuario_atual
    form = JogarForm()
    resultado = ''
    moeda = url_for('static', filename='inicio.png')

    result = random.randint(0, 1)
    ref = dbFire.reference("User")
    emp_ref = ref.get()[usuario_atual]

    if form.validate_on_submit():
        if result == 0:
            moeda = url_for('static', filename='moeda_cara.png')
        else:
            moeda = url_for('static', filename='moeda_coroa.png')
        if int(form.jogar.data) == result:            
            newNum = int(emp_ref['jogos']) + 1
            newVit = int(emp_ref['vitorias']) + 1
            ref.child(usuario_atual).update({
                'jogos': f'{newNum}',
                'vitorias': f'{newVit}'
            })
            resultado = 'Você ganhou'
        else:
            newNum = int(emp_ref['jogos']) + 1
            ref.child(usuario_atual).update({
                'jogos': f'{newNum}',
            })
            resultado = 'Você perdeu'

    return render_template('dashboard.html', nome=str(user), form=form, resultado=resultado, moeda=moeda)


def criarUsuario(usuario):
    ref = dbFire.reference('User')    
    ref.update({
        f'{usuario.username}':
        {
            'name': f'{usuario.username}',
            'senha': f'{usuario.password}',
            'jogos': usuario.nrJogos,
            'vitorias': usuario.ganhos
        }
    })

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        new_user = User(username=form.username.data, password=form.password.data, nrJogos=0, ganhos=0)
        criarUsuario(new_user)
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/resultados', methods=['GET', 'POST'])
def resultados():
    user = dbFire.reference("User").get()[usuario_atual]
    names = ['Vitorias', 'Derrotas']
    vitorias = int(user['vitorias'])
    derrotas = int(user['jogos']) - int(user['vitorias'])
    values = [vitorias, derrotas]
    return render_template('resultados.html', names=names, values=values)

@app.route('/ranking', methods=['GET', 'POST'])
def ranking():
    users = dbFire.reference("User").get()
    return render_template('ranking.html', users=users)

if __name__ == '__main__':
    app.run(debug=True)