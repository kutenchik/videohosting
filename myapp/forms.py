from flask_wtf import FlaskForm,RecaptchaField
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, BooleanField, FileField, DateTimeField, SelectMultipleField, widgets
from wtforms.validators import DataRequired, Email, EqualTo, Length, Optional
from flask_wtf.file import FileAllowed, FileRequired
from myapp.models import User
class RegistrationForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired(), Length(min=4, max=25)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Пароль', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Подтвердите пароль', validators=[DataRequired(), EqualTo('password')])
    recaptcha = RecaptchaField()
    submit = SubmitField('Регистрация')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    remember = BooleanField('Запомнить меня')
    submit = SubmitField('Войти')

class VideoUploadForm(FlaskForm):
    title = StringField('Название видео', validators=[DataRequired()])
    description = TextAreaField('Описание')
    video = FileField('Выберите видео', validators=[FileRequired(), FileAllowed(['mp4', 'avi', 'mov','webm'], 'Только видеофайлы!')])
    thumbnail = FileField('Миниатюра', validators=[FileAllowed(['jpg', 'jpeg', 'png', 'gif'], 'Только изображения!')])
    scheduled_at = DateTimeField('Запланировать публикацию на', format='%Y-%m-%d %H:%M:%S', validators=[Optional()])
    is_archived = BooleanField('Добавить в архив')
    tags = StringField('Теги (через запятую)')
    # Удаляем поле ingredients, так как мы обрабатываем ингредиенты напрямую из request.form
    # ingredients = StringField('Ингредиенты (формат: ингредиент:количество, через запятую)')
    submit = SubmitField('Загрузить')



class EditProfileForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired(), Length(min=4, max=25)])
    bio = TextAreaField('О себе')
    profile_picture = FileField('Аватар', validators=[FileAllowed(['jpg', 'jpeg', 'png', 'gif'], 'Только изображения!')])
    submit = SubmitField('Сохранить изменения')

class SearchForm(FlaskForm):
    search_query = StringField('Поиск', validators=[DataRequired()])
    filters = SelectMultipleField('Фильтры', choices=[('duration', 'Длительность'), ('date', 'Дата'), ('views', 'Просмотры')], option_widget=widgets.CheckboxInput(), widget=widgets.ListWidget(prefix_label=False))
    submit = SubmitField('Найти')

class CommentForm(FlaskForm):
    content = TextAreaField('Комментарий', validators=[DataRequired()])
    submit = SubmitField('Отправить')

class PostForm(FlaskForm):
    content = TextAreaField('Сообщение', validators=[DataRequired()])
    image = FileField('Изображение', validators=[FileAllowed(['jpg', 'jpeg', 'png', 'gif'], 'Только изображения!')])
    is_poll = BooleanField('Создать опрос')
    poll_options = TextAreaField('Варианты ответа (каждый с новой строки)', validators=[Optional()])
    submit = SubmitField('Опубликовать')

class RequestResetForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=100)])
    submit = SubmitField('Отправить инструкцию на почту')
    def validate_email(self, field):
        if not User.query.filter_by(email=field.data).first():
            raise ValueError('Пользователь с таким email не найден.')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('Новый пароль', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField(
        'Повторите пароль',
        validators=[DataRequired(), EqualTo('password', message='Пароли должны совпадать')]
    )
    submit = SubmitField('Сменить пароль')