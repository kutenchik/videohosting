from flask import render_template, redirect, url_for, request, flash, session, send_from_directory, jsonify, Response, g, abort  # Добавил Response
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash  # Добавлен импорт
import os,uuid
import datetime
from sqlalchemy import or_
from myapp import app, db, login_manager

from flask_mail import Mail, Message
from myapp.models import User, Video, Comment, Ingredient, VideoIngredient, Tag, VideoTag, Playlist, PlaylistVideo, VideoLike, Subscription, CommentLike, ViewHistory, Notification, Post, PollOption, Vote, VideoVariant, VideoReport, VideoAppeal
from myapp.forms import RegistrationForm, LoginForm, VideoUploadForm, EditProfileForm, SearchForm, CommentForm, PostForm, ResetPasswordForm ,RequestResetForm
from myapp.utils import get_video_resolution, get_target_qualities, generate_video_variants,get_video_duration,generate_random_filename
import locale
from flask_dance.contrib.google import google
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
locale.setlocale(locale.LC_TIME, 'Russian_Russia')
from itsdangerous import URLSafeTimedSerializer

def generate_reset_token(user_email: str, expires_sec: int = 3600) -> str:
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(user_email, salt='password-reset-salt')

def verify_reset_token(token: str, max_age: int = 3600) -> str | None:
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=max_age)
    except Exception:
        return None
    return email

def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt='email-confirm')

def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt='email-confirm', max_age=expiration)
    except Exception:
        return False
    return email
mail = Mail(app)
DEFAULT_PLAYLISTS = ['Смотреть позже', 'Понравившиеся']
limiter = Limiter(
    key_func=get_remote_address,  # определяет, кто делает запрос (IP)
    #default_limits=["50 per hour"]
    default_limits=[]  
)
limiter.init_app(app)
@app.before_request
def ensure_default_playlists():
    if current_user.is_authenticated:
        # Проверяем, не сделана ли уже эта проверка в рамках одного запроса
        if not getattr(g, 'defaults_checked', False):
            for name in DEFAULT_PLAYLISTS:
                pl = Playlist.query.filter_by(user_id=current_user.user_id, name=name).first()
                if not pl:
                    db.session.add(Playlist(user_id=current_user.user_id,
                                            name=name,
                                            is_private=True))
            db.session.commit()
            g.defaults_checked = True
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
@app.before_request
def block_banned_users():
    # не трогаем ещё не аутентифицированных,
    # и не ломаем доступ к статикам и странице выхода и странице забанен
    allowed_endpoints = {'static', 'logout', 'banned_status', 'login', 'register'}
    if current_user.is_authenticated and getattr(current_user, 'is_banned', False):
        if request.endpoint not in allowed_endpoints:
            # можно сразу логаутить, чтобы current_user перестал быть активным
            logout_user()
            flash('Ваш аккаунт заблокирован. Обратитесь к администратору.', 'danger')
            return redirect(url_for('banned_status'))
@app.route('/banned')
def banned_status():
    # просто информирует пользователя о блокировке
    return render_template('banned.html'), 403
# Маршруты приложения
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        token = generate_reset_token(user.email)
        reset_url = url_for('reset_token', token=token, _external=True)
        msg = Message(
            subject="Запрос на сброс пароля",
            recipients=[user.email]
        )
        msg.body = f"""Здравствуйте, {user.username}!

Чтобы сбросить пароль, перейдите, пожалуйста, по ссылке:
{reset_url}

Если вы не запрашивали сброс пароля, просто проигнорируйте это письмо. Ссылка действительна в течение 1 часа.
"""
        mail.send(msg)

        flash('На вашу почту выслано письмо с инструкцией по сбросу пароля.', 'info')
        return redirect(url_for('login'))
    return render_template('reset_request.html', title='Забыли пароль', form=form)


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    email = verify_reset_token(token)
    if not email:
        flash('Ссылка для сброса пароля недействительна или устарела.', 'warning')
        return redirect(url_for('reset_request'))
    user = User.query.filter_by(email=email).first_or_404()
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.password_hash = generate_password_hash(form.password.data)
        db.session.commit()
        flash('Ваш пароль успешно изменён. Теперь вы можете войти.', 'success')
        return redirect(url_for('login'))
    return render_template('reset_token.html', title='Сброс пароля', form=form)
@app.route('/')
def index():
    now=datetime.datetime.now(datetime.timezone.utc)
    if current_user.is_authenticated:
        # 1) Берём ID всех видео, которые пользователь лайкнул:
        liked_video_ids = [vl.video_id for vl in VideoLike.query
                            .filter_by(user_id=current_user.user_id, like_type=1)
                            .all()]
        if liked_video_ids:
            # 2) Собираем все теги и ингредиенты из этих видео
            liked_tag_ids = {vt.tag_id for vt in VideoTag.query
                                  .filter(VideoTag.video_id.in_(liked_video_ids))
                                  .all()}
            liked_ing_ids = {vi.ingredient_id for vi in VideoIngredient.query
                                   .filter(VideoIngredient.video_id.in_(liked_video_ids))
                                   .all()}

            # 3) Берём все другие видео (не лайкнутые, не бан)
            candidates = Video.query \
                .filter(
                    Video.video_id.notin_(liked_video_ids),
                    Video.is_banned == False,
                    or_(Video.scheduled_at == None, Video.scheduled_at <= now)
                ) \
                .all()

            # 4) Считаем «похожесть» по сумме общих тегов и ингредиентов
            scored = []
            for v in candidates:
                v_tag_ids = {vt.tag_id for vt in v.tags}
                v_ing_ids = {vi.ingredient_id for vi in v.ingredients}
                score = len(v_tag_ids & liked_tag_ids) + len(v_ing_ids & liked_ing_ids)
                if score > 0:
                    scored.append((score, v))

            # 5) Сортируем по убыванию score и берём топ-N
            scored.sort(key=lambda x: x[0], reverse=True)
            recommended_videos = [v for _, v in scored[:10]]
        else:
            # Если лайков нет — просто последние
            recommended_videos = Video.query \
                .filter(
                    Video.is_banned == False,
                    or_(Video.scheduled_at == None, Video.scheduled_at <= now)
                ) \
                .order_by(Video.upload_date.desc()) \
                .limit(10) \
                .all()
    else:
        recommended_videos = Video.query \
            .filter(
                Video.is_banned == False,
                or_(Video.scheduled_at == None, Video.scheduled_at <= now)
            ) \
            .order_by(Video.upload_date.desc()) \
            .limit(10) \
            .all()
    return render_template('index.html', videos=recommended_videos)

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per 10 minutes")
def register():
    form = RegistrationForm()
    
    if request.method == 'POST':

        if form.validate_on_submit():
            existing_user = User.query.filter_by(email=form.email.data).first()
            if existing_user:
                flash('Этот email уже зарегистрирован. Войдите или восстановите пароль.', 'warning')
                return render_template('register.html', form=form)

            hashed_pw = generate_password_hash(form.password.data)
            new_user = User(
                username=form.username.data,
                email=form.email.data,
                password_hash=hashed_pw
            )
            db.session.add(new_user)
            db.session.commit()
            token = generate_confirmation_token(new_user.email)
            confirm_url = url_for('confirm_email', token=token, _external=True)

            msg = Message('Подтверждение регистрации', recipients=[new_user.email])
            msg.body = f"Здравствуйте! Подтвердите свою почту, перейдя по ссылке:\n{confirm_url}"

            mail.send(msg)
            #flash('Письмо для подтверждения отправлено на вашу почту. Проверьте её.', 'info')

            #flash('Регистрация прошла успешно!')
            return redirect(url_for('login'))
        elif request.method == 'POST':
            if 'recaptcha' in form.errors:
                form.recaptcha.errors = ['Пожалуйста, подтвердите, что вы не робот.']
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per 1 minute",methods=["POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if not user.is_email_confirmed:
            flash('Пожалуйста, подтвердите почту перед входом.', 'warning')
            return redirect(url_for('login'))

        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user, remember=form.remember.data)
            flash('Вход выполнен успешно!')
            return redirect(url_for('index'))
        else:
            flash('Неправильный email или пароль.')
    return render_template('login.html', form=form)

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    flash('Вы вышли из системы.')
    return redirect(url_for('index'))


@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    form = VideoUploadForm()
    if request.method == 'POST':
        # Получаем значение из скрытого поля, которое формируется в JavaScript
        scheduled_at_str = request.form.get('scheduled_at')
        scheduled_at = None
        
        # Если в форме передана дата публикации, преобразуем её в объект datetime
        if scheduled_at_str:
            try:
                # Формат: YYYY-MM-DD HH:MM:SS
                scheduled_at = datetime.datetime.strptime(scheduled_at_str, '%Y-%m-%d %H:%M:%S')
            except ValueError:
                flash('Неправильный формат даты и времени', 'error')
                return render_template('upload_video.html', form=form)
        
        if form.validate_on_submit():
            # Определяем расширение исходного файла
            video_ext = os.path.splitext(form.video.data.filename)[1].lower()  # например, ".mp4"
            # Генерируем случайное имя для исходного видео
            video_filename = generate_random_filename(app.config['UPLOAD_FOLDER'], video_ext)
            video_path = os.path.join(app.config['UPLOAD_FOLDER'], video_filename)
            form.video.data.save(video_path)

            # Сохраняем миниатюру (если есть)
            thumbnail_filename = None
            if form.thumbnail.data:
                thumb_ext = os.path.splitext(form.thumbnail.data.filename)[1].lower()
                thumbnail_filename = generate_random_filename(app.config['THUMBNAIL_FOLDER'], thumb_ext)
                thumbnail_path = os.path.join(app.config['THUMBNAIL_FOLDER'], thumbnail_filename)
                form.thumbnail.data.save(thumbnail_path)

            # Определяем длительность исходного видео (если удалось получить)
            duration = get_video_duration(video_path)
            if duration is not None:
                duration = int(duration)  # переводим в целые секунды
            original_quality = get_video_resolution(video_path)
            
            # Создание объекта Video с датой публикации из интерактивного календаря
            new_video = Video(
                user_id=current_user.user_id,
                title=form.title.data,
                description=form.description.data,
                video_url=video_filename,
                thumbnail_url=thumbnail_filename,
                upload_date=datetime.datetime.now(datetime.timezone.utc),
                scheduled_at=scheduled_at,  # Используем новое значение
                # is_archived=form.is_archived.data,
                duration=duration,
                quality=original_quality
            )

            db.session.add(new_video)
            db.session.commit()  # Получаем new_video.video_id

            # Генерация вариантов видео
            original_height = get_video_resolution(video_path)
            target_qualities = get_target_qualities(original_height)
            print(original_height)
            variants_folder = os.path.join(app.config['UPLOAD_FOLDER'], "variants")
            os.makedirs(variants_folder, exist_ok=True)
            # Функция generate_video_variants должна быть адаптирована для генерации имен файлов
            variant_files = generate_video_variants(video_path, variants_folder, target_qualities)
            for quality, variant_filename in variant_files.items():
                # variant_filename уже сгенерирован случайным образом (если функция generate_video_variants так настроена)
                # Если требуется, можно опять вызвать generate_random_filename.
                # Например, можно сделать так:
                variant_ext = os.path.splitext(variant_filename)[1]
                new_variant_filename = generate_random_filename(variants_folder, variant_ext)
                # Переименуем сгенерированный файл, если нужно:
                original_variant_path = os.path.join(variants_folder, variant_filename)
                new_variant_path = os.path.join(variants_folder, new_variant_filename)
                os.rename(original_variant_path, new_variant_path)
                new_variant = VideoVariant(video_id=new_video.video_id, quality=quality, file_url=os.path.join("variants", new_variant_filename).replace("\\", "/"))
                db.session.add(new_variant)
            db.session.commit()

            # Обработка тегов
            tags_list = [tag.strip() for tag in form.tags.data.split(',') if tag.strip()]
            for tag_name in tags_list:
                tag = Tag.query.filter_by(name=tag_name).first()
                if not tag:
                    tag = Tag(name=tag_name)
                    db.session.add(tag)
                    db.session.commit()
                video_tag = VideoTag(video_id=new_video.video_id, tag_id=tag.tag_id)
                db.session.add(video_tag)

            # Обработка ингредиентов
            ingredient_names = request.form.getlist('ingredient_name[]')
            ingredient_amounts = request.form.getlist('ingredient_amount[]')
            for name, amount in zip(ingredient_names, ingredient_amounts):
                name = name.strip()
                amount = amount.strip()
                if name and amount:
                    ingredient = Ingredient.query.filter_by(name=name).first()
                    if not ingredient:
                        ingredient = Ingredient(name=name)
                        db.session.add(ingredient)
                        db.session.commit()
                    video_ing = VideoIngredient(video_id=new_video.video_id, ingredient_id=ingredient.ingredient_id, amount=amount)
                    db.session.add(video_ing)
            db.session.commit()

            # Уведомления подписчикам только если видео публикуется сразу
            if scheduled_at is None:
                for sub in current_user.subscribers:  # обратный join по Subscription
                    n = Notification(
                        recipient_id = sub.subscriber_id,
                        actor_id     = current_user.user_id,
                        verb         = 'uploaded_video',
                        target_video_id = new_video.video_id
                    )
                    db.session.add(n)
                db.session.commit()
                flash('Видео загружено и опубликовано успешно!')
            else:
                flash(f'Видео загружено и будет опубликовано {scheduled_at.strftime("%d.%m.%Y в %H:%M")}!')
                
            return redirect(url_for('index'))
    return render_template('upload_video.html', form=form)

@app.route('/delete_video/<int:video_id>', methods=['POST'])
@login_required
def delete_video(video_id):
    video = Video.query.get_or_404(video_id)
    if video.user_id != current_user.user_id:
        flash('У вас нет прав на удаление этого видео.')
        return redirect(url_for('watch_video', video_id=video_id))

    # Определяем пути к файлам:
    original_video_path = os.path.join(app.config['UPLOAD_FOLDER'], video.video_url)
    if os.path.exists(original_video_path):
        os.remove(original_video_path)

    if video.thumbnail_url:
        thumbnail_path = os.path.join(app.config['THUMBNAIL_FOLDER'], video.thumbnail_url)
        if os.path.exists(thumbnail_path):
            os.remove(thumbnail_path)

    # Удаляем варианты видео (они хранятся в папке variants)
    for variant in video.variants:
        variant_path = os.path.join(app.config['UPLOAD_FOLDER'], variant.file_url)
        if os.path.exists(variant_path):
            os.remove(variant_path)

    # Если у вас есть субтитры, аналогичным образом можно удалить их файлы
    # Если используете модель VideoSubtitle, например:
    # for subtitle in video.subtitles:
    #     subtitle_path = os.path.join(app.config['UPLOAD_FOLDER'], subtitle.file_url)
    #     if os.path.exists(subtitle_path):
    #         os.remove(subtitle_path)

    # Затем удаляем запись видео из базы
    db.session.delete(video)
    db.session.commit()
    flash('Видео и все связанные файлы успешно удалены.')
    return redirect(url_for('profile', username=current_user.username))



@app.route('/video/<int:video_id>', methods=['GET', 'POST'])
def watch_video(video_id):
    video = Video.query.get_or_404(video_id)
    if video.is_banned:
        flash('Это видео больше недоступно.')
        return redirect(url_for('index'))
    # Проверка публикации видео (архив/запланировано)
    if video.is_archived:
        flash('Это видео находится в архиве.')
        return redirect(url_for('index'))
    if video.scheduled_at and video.scheduled_at > datetime.datetime.now(datetime.timezone.utc):
        flash('Это видео еще не опубликовано.')
        return redirect(url_for('index'))

    # Увеличение счетчика просмотров
    video.views += 1
    db.session.commit()
    if current_user.is_authenticated:
        history_entry = ViewHistory.query.filter_by(
            user_id=current_user.user_id,
            video_id=video.video_id
        ).first()
        if history_entry:
            history_entry.viewed_at = datetime.datetime.now(datetime.timezone.utc)
        else:
            history_entry = ViewHistory(user_id=current_user.user_id, video_id=video.video_id)
            db.session.add(history_entry)
        db.session.commit()

    # Обработка отправки комментария или ответа
    if request.method == 'POST':
        if current_user.is_authenticated:
            # Если пришёл ответ (форма с reply_content) или обычный комментарий (из формы form)
            parent_comment_id = request.form.get('parent_comment_id')
            if 'reply_content' in request.form and request.form.get('reply_content').strip():
                content = request.form.get('reply_content').strip()
            elif 'content' in request.form and request.form.get('content').strip():
                content = request.form.get('content').strip()
            else:
                content = ''
            if content:
                new_comment = Comment(
                    video_id=video.video_id,
                    user_id=current_user.user_id,
                    content=content,
                    parent_comment_id=parent_comment_id if parent_comment_id else None
                )
                db.session.add(new_comment)
                db.session.commit()
                flash('Комментарий добавлен.')

                # Если это ответ на комментарий, создаём уведомление для автора родительского комментария
                if parent_comment_id:
                    parent = Comment.query.get(parent_comment_id)
                    if parent and parent.user_id != current_user.user_id:
                        n = Notification(
                            recipient_id     = parent.user_id,
                            actor_id         = current_user.user_id,
                            verb             = 'reply_comment',
                            target_comment_id= parent.comment_id
                        )
                        db.session.add(n)
                        db.session.commit()
                return redirect(url_for('watch_video', video_id=video.video_id))

            else:
                flash('Комментарий не может быть пустым.')
        else:
            flash('Пожалуйста, войдите в систему, чтобы оставить комментарий.')
            return redirect(url_for('login'))

    # Получаем комментарии (без ответов – ответы будут доступны через relationship replies)
    comments = Comment.query.filter_by(video_id=video.video_id, parent_comment_id=None,is_banned=False).order_by(Comment.created_at.desc()).all()
    
    # Получаем похожие видео (логика подбирается по вашему алгоритму)
    
    is_subscribed = False
    if current_user.is_authenticated:
        is_subscribed = Subscription.query.filter_by(
            subscriber_id=current_user.user_id,
            subscribed_to_id=video.author.user_id
        ).first() is not None
    playlists = []
    if current_user.is_authenticated:
        playlists = Playlist.query.filter_by(user_id=current_user.user_id).all()
    playlist_context = None
    playlist_videos  = []
    current_index    = None

    pl_id = request.args.get('playlist_id', type=int)
    if pl_id:
        playlist_context = Playlist.query.get(pl_id)
        if playlist_context:
            # 🛡 Проверка приватности
            if playlist_context.is_private:
                if not current_user.is_authenticated or current_user.user_id != playlist_context.user_id:
                    flash('Этот плейлист приватный.')
                    return redirect(url_for('index'))

            entries = (playlist_context.videos
                                .order_by(PlaylistVideo.position)
                                .all())
            playlist_videos = [e.video for e in entries]
            for i, v in enumerate(playlist_videos):
                if v.video_id == video.video_id:
                    current_index = i
                    break
    base_tag_ids = {vt.tag_id for vt in video.tags}
    base_ing_ids = {vi.ingredient_id for vi in video.ingredients}

    # Выбираем кандидатов (остальные, не забаненные)
    candidates = Video.query \
        .filter(Video.video_id != video.video_id,
                Video.is_banned == False) \
        .all()

    # Считаем количество совпадений
    scored = []
    for v in candidates:
        v_tag_ids = {vt.tag_id for vt in v.tags}
        v_ing_ids = {vi.ingredient_id for vi in v.ingredients}
        score = len(v_tag_ids & base_tag_ids) + len(v_ing_ids & base_ing_ids)
        if score > 0:
            scored.append((score, v))

    # Сортируем и берём топ-4
    scored.sort(key=lambda x: x[0], reverse=True)
    similar_videos = [v for _, v in scored[:4]]
    return render_template('video.html', video=video, form=CommentForm(), comments=comments,
                        similar_videos=similar_videos, Comment=Comment, is_subscribed=is_subscribed,
                        playlists=playlists, playlist_context=playlist_context,
                           playlist_videos=playlist_videos,
                           current_index=current_index)


@app.route('/delete_comment/<int:comment_id>', methods=['POST'])
@login_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    # Проверяем, что автор комментария совпадает с текущим пользователем
    if comment.user_id != current_user.user_id:
        flash('У вас нет прав на удаление этого комментария.')
        # Можно перенаправлять на страницу видео
        return redirect(url_for('watch_video', video_id=comment.video_id))
    db.session.delete(comment)
    db.session.commit()
    flash('Комментарий успешно удалён.')
    return redirect(url_for('watch_video', video_id=comment.video_id))



@app.route('/like_video/<int:video_id>', methods=['POST'])
@limiter.limit("10 per minute")
@login_required
def like_video(video_id):
    video = Video.query.get_or_404(video_id)
    like_type = int(request.form.get('like_type'))
    existing_like = VideoLike.query.filter_by(user_id=current_user.user_id, video_id=video_id).first()

    removed_like = False
    if existing_like:
        if existing_like.like_type == like_type:
            db.session.delete(existing_like)
            removed_like = True
        else:
            existing_like.like_type = like_type
    else:
        db.session.add(VideoLike(user_id=current_user.user_id, video_id=video_id, like_type=like_type))

    db.session.commit()

    # Обновим плейлист «Понравившиеся»
    liked_pl = Playlist.query.filter_by(user_id=current_user.user_id, name='Понравившиеся').first()
    if liked_pl:
        entry = PlaylistVideo.query.filter_by(playlist_id=liked_pl.playlist_id, video_id=video_id).first()
        if like_type == 1 and not entry:
            max_pos = db.session.query(db.func.max(PlaylistVideo.position)) \
                                .filter_by(playlist_id=liked_pl.playlist_id).scalar() or 0
            db.session.add(PlaylistVideo(playlist_id=liked_pl.playlist_id, video_id=video_id, position=max_pos + 1))
        elif (like_type != 1 or removed_like) and entry:
            db.session.delete(entry)
    db.session.commit()

    return jsonify({'status': 'success'})


@app.route('/like_comment/<int:comment_id>', methods=['POST'])
@login_required
def like_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    existing_like = CommentLike.query.filter_by(user_id=current_user.user_id, comment_id=comment_id).first()
    if existing_like:
        db.session.delete(existing_like)
    else:
        new_like = CommentLike(user_id=current_user.user_id, comment_id=comment_id)
        db.session.add(new_like)
    db.session.commit()
    return jsonify({'status': 'success'})

@app.route('/subscribe/<int:user_id>', methods=['POST'])
@login_required
def subscribe(user_id):
    user_to_subscribe = User.query.get_or_404(user_id)
    existing_sub = Subscription.query.filter_by(subscriber_id=current_user.user_id, subscribed_to_id=user_id).first()
    if existing_sub:
        db.session.delete(existing_sub)
        message = 'Вы отписались от пользователя.'
    else:
        new_sub = Subscription(subscriber_id=current_user.user_id, subscribed_to_id=user_id)
        db.session.add(new_sub)
        message = 'Вы подписались на пользователя.'
        # Добавляем уведомление
        if not existing_sub:
            n = Notification(
                recipient_id = user_to_subscribe.user_id,
                actor_id     = current_user.user_id,
                verb         = 'subscribed'
            )
            db.session.add(n)
    db.session.commit()
    flash(message)
    return redirect(url_for('profile', username=user_to_subscribe.username))

@app.route('/api/notifications')
@login_required
def api_notifications():
    month_ago = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=30)
    notifs = Notification.query \
        .filter(Notification.recipient_id == current_user.user_id,
                Notification.created_at >= month_ago,
                Notification.is_hidden == False) \
        .order_by(Notification.created_at.desc()) \
        .all()


    def serialize(n):
        base = {
            "id": n.notification_id,
            "verb": n.verb,
            "actor": {
                "id": n.actor.user_id,
                "username": n.actor.username,
                "avatar": url_for('static', filename='uploads/'+n.actor.profile_picture)
            },
            "created_at": n.created_at.isoformat(),
            "read": n.is_read,
            "hidden": n.is_hidden
        }
        if n.verb=='uploaded_video':
            base["video"] = {
                "id": n.target_video_id,
                "title": Video.query.get(n.target_video_id).title,
                "thumbnail": url_for('static', filename='thumbnails/'+Video.query.get(n.target_video_id).thumbnail_url)
            }
        elif n.verb == 'reply_comment':
            comment = Comment.query.get(n.target_comment_id)
            base["message"] = f"{n.actor.username} ответил на ваш комментарий: «{comment.content[:50]}…»"
            base["video"] = {
                "id": comment.video_id
            }
            base["target_comment_id"] = comment.comment_id

        elif n.verb=='subscribed':
            base["message"] = f"{n.actor.username} подписался на вас"
        return base

    return jsonify([serialize(n) for n in notifs])
@app.route('/api/notifications/<int:notification_id>/read', methods=['POST'])
@login_required
def mark_notification_as_read(notification_id):
    notif = Notification.query.get_or_404(notification_id)
    if notif.recipient_id != current_user.user_id:
        return jsonify({'error': 'Нет доступа'}), 403

    notif.is_read = True
    db.session.commit()
    return jsonify({'success': True})
@app.route('/api/notifications/<int:notification_id>/unread', methods=['POST'])
@login_required
def mark_notification_unread(notification_id):
    notif = Notification.query.filter_by(id=notification_id, user_id=current_user.id).first()
    if notif:
        notif.read = False
        db.session.commit()
        return jsonify({'status': 'ok'}), 200
    return jsonify({'error': 'not found'}), 404

@app.route('/api/notifications/<int:notification_id>/hide', methods=['POST'])
@login_required
def hide_notification(notification_id):
    notif = Notification.query.get_or_404(notification_id)
    if notif.recipient_id != current_user.user_id:
        return jsonify({'error': 'Нет доступа'}), 403

    notif.is_hidden = True
    db.session.commit()
    return jsonify({'success': True})

@app.route('/profile/<username>')
def profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    # получаем таб из query string, по умолчанию 'videos'
    active_tab = request.args.get('tab', 'videos')
    now = datetime.datetime.now(datetime.timezone.utc)
    videos = Video.query.filter(Video.user_id == user.user_id, 
             or_(Video.scheduled_at == None, 
                 Video.scheduled_at <= now)).order_by(Video.upload_date.desc()).all()
    posts = Post.query.filter_by(user_id=user.user_id,is_banned=False).order_by(Post.created_at.desc()).all()
    playlists = Playlist.query.filter_by(user_id=user.user_id).all()
    watch_history = (
        ViewHistory.query
        .join(Video, ViewHistory.video)   # связываем с Video
        .filter(
            ViewHistory.user_id == user.user_id,
            Video.is_banned == False      # только не забаненные
        )
        .order_by(ViewHistory.viewed_at.desc())
        .all()
    )
    is_subscribed = False
    banned_videos = []
    if current_user.is_authenticated and current_user.user_id == user.user_id:
        banned_videos = [v for v in user.videos if v.is_banned]
    if current_user.is_authenticated:
        is_subscribed = Subscription.query.filter_by(
            subscriber_id=current_user.user_id,
            subscribed_to_id=user.user_id
        ).first() is not None
    return render_template(
        'profile.html',
        user=user,
        videos=videos,
        posts=posts,
        playlists=playlists,
        watch_history=watch_history,
        is_subscribed=is_subscribed,
        active_tab=active_tab,
        banned_videos=banned_videos
    )



@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm(obj=current_user)
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.bio = form.bio.data
        if form.profile_picture.data:
            pic_filename = secure_filename(form.profile_picture.data.filename)
            form.profile_picture.data.save(os.path.join(app.config['UPLOAD_FOLDER'], pic_filename))
            current_user.profile_picture = pic_filename
        db.session.commit()
        flash('Профиль обновлен.')
        return redirect(url_for('profile', username=current_user.username))
    return render_template('edit_profile.html', form=form)

@app.route('/search')
def search():
    # Получаем параметры из GET-запроса
    query_str = request.args.get('q', '')
    type_filter = request.args.get('type', 'all')  # 'all', 'video', 'channel' или 'playlist'
    now=datetime.datetime.now(datetime.timezone.utc)
    # Дополнительные параметры для фильтрации видео
    date_filter = request.args.get('date_filter', '')     # например: today, week, month, year
    duration_filter = request.args.get('duration_filter', '') # 'short', 'medium', 'long'
    order_by = request.args.get('order_by', 'date')         # 'date' или 'views'

    results = {}
    if query_str:
        if type_filter in ['all', 'video']:
            # Поиск по видео через объединение с тегами и ингредиентами
            video_query = Video.query \
                .outerjoin(VideoTag, Video.video_id == VideoTag.video_id) \
                .outerjoin(Tag, VideoTag.tag_id == Tag.tag_id) \
                .outerjoin(VideoIngredient, Video.video_id == VideoIngredient.video_id) \
                .outerjoin(Ingredient, VideoIngredient.ingredient_id == Ingredient.ingredient_id) \
                .filter(
                    or_(
                        Video.title.ilike(f'%{query_str}%'),
                        Tag.name.ilike(f'%{query_str}%'),
                        Ingredient.name.ilike(f'%{query_str}%')
                    )
                ).distinct()
            video_query = video_query.filter(
                or_(Video.scheduled_at == None, Video.scheduled_at <= now),
                Video.is_banned == False
            )
            # Фильтрация по дате загрузки
            if date_filter:
                now = datetime.datetime.now(datetime.timezone.utc)
                if date_filter == 'today':
                    start = datetime.datetime(now.year, now.month, now.day)
                elif date_filter == 'week':
                    start = now - datetime.timedelta(days=7)
                elif date_filter == 'month':
                    start = now - datetime.timedelta(days=30)
                elif date_filter == 'year':
                    start = now - datetime.timedelta(days=365)
                video_query = video_query.filter(Video.upload_date >= start)
            # Фильтрация по длительности (в секундах)
            if duration_filter:
                print(Video.duration)
                if duration_filter == 'short':
                    video_query = video_query.filter(Video.duration < 4 * 60)
                elif duration_filter == 'medium':
                    video_query = video_query.filter(Video.duration >= 4 * 60, Video.duration <= 20 * 60)
                elif duration_filter == 'long':
                    video_query = video_query.filter(Video.duration > 20 * 60)
            # Сортировка
            if order_by == 'views':
                video_query = video_query.order_by(Video.views.desc())
            else:
                video_query = video_query.order_by(Video.upload_date.desc())
            results['video'] = video_query.all()
        if type_filter in ['all', 'channel']:
            # Поиск каналов (по имени и email)
            user_query = User.query.filter(
                or_(
                    User.username.ilike(f'%{query_str}%'),
                    User.email.ilike(f'%{query_str}%')
                )
            )
            results['channel'] = user_query.all()
        if type_filter in ['all', 'playlist']:
            # Поиск плейлистов (по названию)
            playlist_query = Playlist.query.filter(
                Playlist.name.ilike(f'%{query_str}%')
            )
            results['playlist'] = playlist_query.all()
    else:
        results = None  # Если поисковая строка пуста, можно вернуть пустые результаты

    return render_template('search.html',
                           query=query_str,
                           type_filter=type_filter,
                           date_filter=date_filter,
                           duration_filter=duration_filter,
                           order_by=order_by,
                           results=results)
@app.route('/download/<filename>')
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

@app.route('/post', methods=['GET', 'POST'])
@login_required
def create_post():
    form = PostForm()
    if form.validate_on_submit():
        new_post = Post(
            user_id=current_user.user_id,
            content=form.content.data,
            is_poll=form.is_poll.data
        )
        if form.image.data:
            image_filename = secure_filename(form.image.data.filename)
            form.image.data.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))
            new_post.image_url = image_filename
        db.session.add(new_post)
        db.session.commit()
        # Если пост является опросом и заданы варианты
        if new_post.is_poll and form.poll_options.data.strip():
            options = form.poll_options.data.strip().splitlines()
            for option in options:
                option = option.strip()
                if option:
                    poll_option = PollOption(post_id=new_post.post_id, option_text=option)
                    db.session.add(poll_option)
            db.session.commit()
        flash('Публикация создана.')
        return redirect(url_for('profile', username=current_user.username))
    return render_template('post.html', form=form)
@app.route('/delete_post/<int:post_id>', methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    # Проверка, что пост принадлежит текущему пользователю
    if post.user_id != current_user.user_id:
        flash('У вас нет прав на удаление этой публикации.')
        return redirect(url_for('profile', username=current_user.username))
    db.session.delete(post)
    db.session.commit()
    flash('Публикация успешно удалена.')
    return redirect(url_for('profile', username=current_user.username))

@app.route('/vote/<int:option_id>', methods=['POST'])
@login_required
def vote(option_id):
    poll_option = PollOption.query.get_or_404(option_id)
    # Ищем, голосовал ли уже пользователь в этом опросе
    existing_vote = Vote.query.join(PollOption).filter(
        Vote.user_id == current_user.user_id,
        PollOption.post_id == poll_option.post_id
    ).first()
    if existing_vote:
        if existing_vote.option_id == option_id:
            # Если пользователь кликает по тому же варианту – отменяем голос
            db.session.delete(existing_vote)
            db.session.commit()
            flash('Ваш голос отменен.')
        else:
            # Если голос уже был, но за другой вариант – обновляем голос
            existing_vote.option_id = option_id
            db.session.commit()
            flash('Ваш голос обновлен.')
    else:
        new_vote = Vote(user_id=current_user.user_id, option_id=option_id)
        db.session.add(new_vote)
        db.session.commit()
        flash('Ваш голос учтен.')
    # Перенаправляем на страницу просмотра поста. Предположим, у вас есть маршрут view_post
    # Если голосование происходит прямо на странице профиля, можно перенаправлять на профиль или обновлять страницу через AJAX.
    return redirect(url_for('view_post', post_id=poll_option.post_id))


@app.route('/post/<int:post_id>')
def view_post(post_id):
    post = Post.query.get_or_404(post_id)
    return render_template('view_post.html', post=post)


@app.route('/livestream')
def livestream():
    return render_template('livestream.html')

# Маршрут для стрима (заглушка)
@app.route('/stream')
def stream():
    return Response(gen(), mimetype='multipart/x-mixed-replace; boundary=frame')

def gen():
    while True:
        frame = get_video_frame()  # Реализуйте функцию получения кадра
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')

def get_video_frame():
    # Заглушка: возвращаем пустые байты
    return b''


# Дополнительные маршруты для управления плейлистами

@app.route('/create_playlist', methods=['GET', 'POST'])
@login_required
def create_playlist():
    if request.method == 'POST':
        name = request.form.get('name')
        privacy = request.form.get('privacy')  # public или private
        is_private = (privacy == 'private')

        # Пример: создание плейлиста
        playlist = Playlist(
            name=name,
            user_id=current_user.user_id,
            is_private=is_private
        )
        db.session.add(playlist)
        db.session.commit()
        flash('Плейлист создан успешно!')
        return redirect(url_for('profile', username=current_user.username))  # Или куда нужно

    return render_template('create_playlist.html')


@app.route('/add_to_playlist/<int:video_id>', methods=['POST'])
@login_required
def add_to_playlist(video_id):
    playlist_id = request.form.get('playlist_id')
    if not playlist_id:
        flash('Не выбран плейлист.')
        return redirect(url_for('watch_video', video_id=video_id))

    playlist = Playlist.query.get_or_404(int(playlist_id))
    if playlist.user_id != current_user.user_id:
        flash('Вы не можете добавлять видео в этот плейлист.')
        return redirect(url_for('watch_video', video_id=video_id))

    existing_entry = PlaylistVideo.query.filter_by(playlist_id=playlist.playlist_id, video_id=video_id).first()
    if existing_entry:
        flash('Видео уже добавлено в этот плейлист.')
        return redirect(url_for('watch_video', video_id=video_id))

    max_pos = db.session.query(db.func.max(PlaylistVideo.position)) \
                        .filter_by(playlist_id=playlist.playlist_id) \
                        .scalar() or 0
    db.session.add(PlaylistVideo(playlist_id=playlist.playlist_id, video_id=video_id, position=max_pos + 1))

    # Если плейлист — «Понравившиеся», добавим лайк
    if playlist.name == 'Понравившиеся':
        like = VideoLike.query.filter_by(user_id=current_user.user_id, video_id=video_id).first()
        if not like:
            db.session.add(VideoLike(user_id=current_user.user_id, video_id=video_id, like_type=1))
        elif like.like_type != 1:
            like.like_type = 1

    db.session.commit()
    flash('Видео добавлено в плейлист.')
    return redirect(url_for('watch_video', video_id=video_id, playlist_id=playlist.playlist_id))
@app.route('/api/playlist/<int:playlist_id>/remove/<int:video_id>', methods=['POST'])
@login_required
def api_remove_from_playlist(playlist_id, video_id):
    playlist = Playlist.query.get_or_404(playlist_id)

    if playlist.user_id != current_user.user_id:
        return jsonify({'error': 'Нет доступа'}), 403

    entry = PlaylistVideo.query.filter_by(playlist_id=playlist_id, video_id=video_id).first()
    if not entry:
        return jsonify({'error': 'Видео не найдено в плейлисте'}), 404

    db.session.delete(entry)

    # Если это "Понравившиеся", убираем также лайк
    if playlist.name == 'Понравившиеся':
        like = VideoLike.query.filter_by(user_id=current_user.user_id, video_id=video_id).first()
        if like:
            db.session.delete(like)

    db.session.commit()
    return jsonify({'status': 'success'})


@app.route('/playlist/<int:pl_id>/move/<int:vid_id>/<string:direction>', methods=['POST'])
@login_required
def move_in_playlist(pl_id, vid_id, direction):
    playlist = Playlist.query.get_or_404(pl_id)
    if playlist.user_id != current_user.user_id:
        abort(403)
    pv = PlaylistVideo.query.filter_by(playlist_id=pl_id, video_id=vid_id).first_or_404()
    if direction == 'prev':
        other = PlaylistVideo.query.filter_by(
            playlist_id=pl_id, position=pv.position - 1
        ).first()
    else:
        other = PlaylistVideo.query.filter_by(
            playlist_id=pl_id, position=pv.position + 1
        ).first()
    if other:
        pv.position, other.position = other.position, pv.position
        db.session.commit()
    return jsonify(status='success')


@app.route('/playlist/<int:playlist_id>/reorder', methods=['POST'])
@login_required
def reorder_playlist(playlist_id):
    data = request.get_json() or {}
    order = data.get('order', [])
    playlist = Playlist.query.get_or_404(playlist_id)
    if playlist.user_id != current_user.user_id:
        return jsonify({'error': 'Unauthorized'}), 403

    # Обновляем position у каждой связи
    for idx, vid_id in enumerate(order, start=1):
        pv = PlaylistVideo.query.filter_by(
            playlist_id=playlist_id,
            video_id=int(vid_id)
        ).first()
        if pv:
            pv.position = idx
    db.session.commit()
    return jsonify({'status': 'ok'})


@app.route('/playlist/<int:playlist_id>')
def view_playlist(playlist_id):
    playlist = Playlist.query.get_or_404(playlist_id)

    # 🔒 Проверка приватности
    if playlist.is_private:
        if not current_user.is_authenticated or current_user.user_id != playlist.user_id:
            flash('Этот плейлист приватный.')
            return redirect(url_for('index'))

    videos = [
    entry.video 
    for entry in playlist.videos 
    if not entry.video.is_banned
]
    return render_template('view_playlist.html', playlist=playlist, videos=videos)

@app.route('/playlist/<int:playlist_id>/save', methods=['POST'])
@login_required
def save_playlist(playlist_id):
    original = Playlist.query.get_or_404(playlist_id)

    # ---------------------------------------------------
    # ✖ запретить клонирование системных плейлистов
    if original.name in DEFAULT_PLAYLISTS:
        flash('Нельзя сохранять системный плейлист.')
        return redirect(url_for('watch_video',
                                video_id=request.args.get('video_id', original.videos[0].video_id),
                                playlist_id=playlist_id))
    # ---------------------------------------------------

    new_pl = Playlist(
        user_id=current_user.user_id,
        name=original.name,
        is_private=original.is_private
    )
    db.session.add(new_pl)
    db.session.commit()

    entries = (PlaylistVideo.query
               .filter_by(playlist_id=original.playlist_id)
               .order_by(PlaylistVideo.position)
               .all())
    for e in entries:
        clone = PlaylistVideo(
            playlist_id=new_pl.playlist_id,
            video_id=e.video_id,
            position=e.position
        )
        db.session.add(clone)
    db.session.commit()

    flash(f'Плейлист «{new_pl.name}» сохранён.')
    return redirect(url_for('view_playlist', playlist_id=new_pl.playlist_id))
@app.route('/history')
@login_required
def history():
    view_history = ViewHistory.query.filter_by(user_id=current_user.user_id)\
                      .order_by(ViewHistory.viewed_at.desc()).all()
    return render_template('watch_history.html', view_history=view_history)


@app.route('/history/delete/<int:history_id>', methods=['POST'])
@login_required
def delete_history(history_id):
    history_entry = ViewHistory.query.get_or_404(history_id)
    if history_entry.user_id != current_user.user_id:
        flash('У вас нет прав для удаления этой записи.')
        return redirect(url_for('history'))
    db.session.delete(history_entry)
    db.session.commit()
    flash('Запись успешно удалена из истории просмотров.')
    return redirect(url_for('history'))
@app.route('/watch_later')
@login_required
def watch_later():
    pl = Playlist.query.filter_by(user_id=current_user.user_id, name='Смотреть позже').first_or_404()
    videos = (
        pl.videos
          .order_by(PlaylistVideo.added_at.desc())
          .all()
    )
    # view_playlist.html — тот же шаблон, что и для обычных плейлистов
    return render_template('view_playlist.html', playlist=pl, videos=[pv.video for pv in videos])
@app.route('/api/watch_later/<int:video_id>', methods=['POST'])
@login_required
def add_to_watch_later(video_id):
    watch_later_playlist = Playlist.query.filter_by(user_id=current_user.user_id, name='Смотреть позже').first()
    if not watch_later_playlist:
        watch_later_playlist = Playlist(user_id=current_user.user_id, name='Смотреть позже')
        db.session.add(watch_later_playlist)
        db.session.commit()

    # Проверим, уже добавлено ли видео
    existing = PlaylistVideo.query.filter_by(playlist_id=watch_later_playlist.playlist_id, video_id=video_id).first()
    if not existing:
        db.session.add(PlaylistVideo(playlist_id=watch_later_playlist.playlist_id, video_id=video_id))
        db.session.commit()

    return jsonify({'status': 'success'})

@app.route('/liked')
@login_required
def liked():
    pl = Playlist.query.filter_by(user_id=current_user.user_id, name='Понравившиеся').first_or_404()
    videos = (
        pl.videos
          .order_by(PlaylistVideo.added_at.desc())
          .all()
    )
    return render_template('view_playlist.html', playlist=pl, videos=[pv.video for pv in videos])
@app.route('/subscriptions')
@login_required
def subscriptions():
    channel_ids = [sub.subscribed_to_id for sub in current_user.subscriptions]
    channels = User.query \
        .filter(User.user_id.in_(channel_ids)) \
        .order_by(User.username) \
        .all()

    week_ago = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=7)

    subscription_videos = Video.query \
        .filter(
            Video.user_id.in_(channel_ids),
            Video.upload_date >= week_ago
        ) \
        .order_by(Video.upload_date.desc()) \
        .all()

    return render_template(
        'subscriptions.html',
        channels=channels,
        subscription_videos=subscription_videos
    )

@app.route('/delete_playlist/<int:playlist_id>', methods=['POST'])
@login_required
def delete_playlist(playlist_id):
    pl = Playlist.query.get_or_404(playlist_id)
    if pl.name in DEFAULT_PLAYLISTS or pl.user_id != current_user.user_id:
        return jsonify(success=False), 403

    db.session.delete(pl)
    db.session.commit()

    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify(success=True)
    flash('Плейлист удалён.')
    return redirect(url_for('profile', username=current_user.username))
@app.route('/update_playlist/<int:playlist_id>', methods=['POST'])
@login_required
def update_playlist(playlist_id):
    data = request.get_json() or {}
    new_name = data.get('name', '').strip()
    # ✖ пустое или «системное» имя — нельзя
    if not new_name or new_name in DEFAULT_PLAYLISTS:
        return jsonify(success=False, error='Недопустимое имя'), 400

    pl = Playlist.query.get_or_404(playlist_id)
    if pl.user_id != current_user.user_id:
        return jsonify(success=False, error='Нет прав'), 403

    pl.name = new_name
    db.session.commit()
    return jsonify(success=True)

@app.route('/playlists')
@login_required
def playlists():
    # Список всех плейлистов пользователя
    pls = Playlist.query.filter_by(user_id=current_user.user_id)\
                        .order_by(Playlist.created_at.desc()).all()
    return render_template('playlists.html', playlists=pls)
@app.route('/report_video/<int:video_id>', methods=['POST'])
@login_required
def report_video(video_id):
    video = Video.query.get_or_404(video_id)
    reason = request.form.get('reason','').strip()
    if not reason:
        flash('Нужно указать причину жалобы.', 'warning')
        return redirect(request.referrer or url_for('watch_video', video_id=video_id))

    db.session.add(VideoReport(
        video_id=video.video_id,
        reporter_id=current_user.user_id,
        reason=reason
    ))
    db.session.commit()
    flash('Спасибо, ваша жалоба отправлена администратору.', 'success')
    return redirect(url_for('watch_video', video_id=video_id))
@app.errorhandler(429)
def ratelimit_handler(e):
    return render_template("ratelimit.html", error=e), 429
@app.route("/google_login")
def google_login():

    if not google.authorized:
        return redirect(url_for("google.login"))

    resp = google.get("/oauth2/v2/userinfo")
    if not resp.ok:
        flash("Не удалось получить информацию от Google", "danger")
        return redirect(url_for("login"))

    info = resp.json()
    email = info["email"]
    name = info.get("name", email.split("@")[0])

    user = User.query.filter_by(email=email).first()
    if not user:
        # Если пользователь не найден — создаём
        user = User(username=name, email=email,is_email_confirmed=True, password_hash=generate_password_hash(str(uuid.uuid4())))
        db.session.add(user)
        db.session.commit()

    login_user(user)
    flash("Вы вошли через Google", "success")
    return redirect(url_for("index"))
@app.route('/confirm/<token>')
def confirm_email(token):
    email = confirm_token(token)
    if not email:
        flash('Ссылка недействительна или истекла.', 'danger')
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first_or_404()
    if user.is_email_confirmed:
        flash('Почта уже подтверждена. Можете войти.', 'info')
    else:
        user.is_email_confirmed = True
        db.session.commit()
        flash('Спасибо! Ваша почта подтверждена.', 'success')
    return redirect(url_for('login'))
@app.route('/appeal/<int:video_id>', methods=['POST'])
@login_required
def appeal_video(video_id):
    video = Video.query.get_or_404(video_id)
    if not video.is_banned:
        flash('Нельзя подать аппеляцию на активное видео', 'warning')
        return redirect(request.referrer)
    reason = request.form.get('reason', '').strip()
    if not reason:
        flash('Укажите причину аппеляции', 'danger')
        return redirect(request.referrer)
    appeal = VideoAppeal(video_id=video_id, user_id=current_user.user_id, reason=reason)
    db.session.add(appeal)
    db.session.commit()
    flash('Аппеляция отправлена', 'success')
    return redirect(url_for('profile', username=current_user.username))

