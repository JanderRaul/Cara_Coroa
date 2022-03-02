import random
from flask import Flask, render_template, session, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, RadioField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt

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
    return User.query.get(int(user_id))

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
        existing_user_name = User.query.filter_by(username=username.data).first()
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
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))

    return render_template('login.html', form=form)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    user = User.query.get(current_user.id)
    form = JogarForm()
    resultado = ''
    moeda = url_for('static', filename='inicio.png')

    result = random.randint(0, 1)

    if form.validate_on_submit():
        if result == 0:
            moeda = url_for('static', filename='moeda_cara.png')
        else:
            moeda = url_for('static', filename='moeda_coroa.png')
        if int(form.jogar.data) == result:
            newNum = user.nrJogos + 1
            newVit = user.ganhos + 1
            db.session.query(User).filter(User.id == user.id).update({User.nrJogos: newNum, User.ganhos: newVit})
            db.session.commit()
            resultado = 'Você ganhou'
        else:
            newNum = user.nrJogos + 1
            db.session.query(User).filter(User.id == user.id).update({User.nrJogos: newNum})
            db.session.commit()
            resultado = 'Você perdeu'

    return render_template('dashboard.html', nome=str(user.username), form=form, resultado=resultado, moeda=moeda)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password, nrJogos=0, ganhos=0)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/resultados', methods=['GET', 'POST'])
@login_required
def resultados():
    user = User.query.get(current_user.id)
    names = ['Vitorias', 'Derrotas']
    vitorias = user.ganhos
    derrotas = user.nrJogos - user.ganhos
    values = [vitorias, derrotas]
    return render_template('resultados.html', names=names, values=values)

@app.route('/ranking', methods=['GET', 'POST'])
@login_required
def ranking():
    users = User.query.all()
    return render_template('ranking.html', users=users)

if __name__ == '__main__':
    app.run(debug=True)