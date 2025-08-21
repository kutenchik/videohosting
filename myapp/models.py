from myapp import db
from flask_login import UserMixin
import datetime
from sqlalchemy import Enum
from sqlalchemy.sql import func
from sqlalchemy.orm import backref
# Модели базы данных

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )
    profile_picture = db.Column(db.String(255), default='images/default_pfp.png')
    bio = db.Column(db.Text)
    
    is_admin  = db.Column(db.Boolean, default=False, nullable=False)
    is_banned = db.Column(db.Boolean, default=False, nullable=False)
    
    videos = db.relationship('Video', backref='author', lazy=True)
    comments = db.relationship('Comment', backref='author', lazy=True)
    posts = db.relationship('Post', backref='author', lazy=True)
    playlists = db.relationship('Playlist', backref='owner', lazy=True)
    subscriptions = db.relationship('Subscription', foreign_keys='Subscription.subscriber_id', backref='subscriber', lazy='dynamic')
    subscribers = db.relationship('Subscription', foreign_keys='Subscription.subscribed_to_id', backref='subscribed_to', lazy='dynamic')
    received_notifications = db.relationship(
        'Notification',
        foreign_keys='Notification.recipient_id',
        back_populates='recipient',
        lazy='dynamic'
    )
    # (Опционально) Нотификации, которые отправил пользователь
    sent_notifications = db.relationship(
        'Notification',
        foreign_keys='Notification.actor_id',
        back_populates='actor',
        lazy='dynamic'
    )
    confirmation_token = db.Column(db.String(120), nullable=True)
    is_email_confirmed = db.Column(db.Boolean, default=False, nullable=False)
    def get_id(self):
        return str(self.user_id)
class Video(db.Model):
    __tablename__ = 'videos'
    video_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    upload_date = db.Column(
        db.DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )
    duration = db.Column(db.Integer)  # В секундах
    thumbnail_url = db.Column(db.String(255))
    video_url = db.Column(db.String(255), nullable=False)
    views = db.Column(db.Integer, default=0)
    is_archived = db.Column(db.Boolean, default=False)
    scheduled_at = db.Column(
        db.DateTime(timezone=True),
        nullable=True
    )
    quality = db.Column(db.Integer, nullable=True)
    
    comments = db.relationship('Comment', backref='video', lazy='dynamic', cascade="all, delete-orphan")
    likes = db.relationship('VideoLike', backref='video', lazy='dynamic', cascade="all, delete-orphan")
    tags = db.relationship('VideoTag', backref='video', lazy='dynamic', cascade="all, delete-orphan")
    ingredients = db.relationship('VideoIngredient', backref='video', lazy='dynamic', cascade="all, delete-orphan")
    playlists = db.relationship('PlaylistVideo', lazy='dynamic', cascade="all, delete-orphan",passive_deletes=True,back_populates='video')
    view_history = db.relationship('ViewHistory', backref='video', lazy='dynamic', cascade="all, delete-orphan")
    variants = db.relationship('VideoVariant', backref='video', lazy=True, cascade="all, delete-orphan")
    is_banned = db.Column(db.Boolean, default=False, nullable=False)
    # subtitles = db.relationship('VideoSubtitle', backref='video', lazy=True)
class VideoVariant(db.Model):
    __tablename__ = 'video_variants'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    video_id = db.Column(db.Integer, db.ForeignKey('videos.video_id'), nullable=False)
    quality = db.Column(db.Integer, nullable=False)  # Например, 1080, 720, 480, 360, 240, 144
    file_url = db.Column(db.String(255), nullable=False)

# class VideoSubtitle(db.Model):
#     __tablename__ = 'video_subtitles'
#     id = db.Column(db.Integer, primary_key=True, autoincrement=True)
#     video_id = db.Column(db.Integer, db.ForeignKey('videos.video_id'), nullable=False)
#     language = db.Column(db.String(10), nullable=False)  # Например, "ru", "en"
#     label = db.Column(db.String(50), nullable=False)       # Например, "Русские субтитры"
#     file_url = db.Column(db.String(255), nullable=False)


class Comment(db.Model):
    __tablename__ = 'comments'
    comment_id = db.Column(db.Integer, primary_key=True)
    video_id = db.Column(
        db.Integer,
        db.ForeignKey('videos.video_id', ondelete='CASCADE'),
        nullable=False
    )
    user_id = db.Column(
        db.Integer,
        db.ForeignKey('users.user_id', ondelete='CASCADE'),
        nullable=False
    )
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )
    parent_comment_id = db.Column(db.Integer, db.ForeignKey('comments.comment_id'))

    replies = db.relationship(
    'Comment',
    backref=db.backref('parent', remote_side=[comment_id]),
    lazy='dynamic',
    cascade='all, delete-orphan',
    passive_deletes=True
)
    likes = db.relationship('CommentLike', backref='comment', lazy='dynamic')
    is_banned = db.Column(db.Boolean, default=False, nullable=False)

class Ingredient(db.Model):
    __tablename__ = 'ingredients'
    ingredient_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)

class VideoIngredient(db.Model):
    __tablename__ = 'video_ingredients'
    video_id = db.Column(db.Integer, db.ForeignKey('videos.video_id'), primary_key=True)
    ingredient_id = db.Column(db.Integer, db.ForeignKey('ingredients.ingredient_id'), primary_key=True)
    amount = db.Column(db.String(50))

    ingredient = db.relationship('Ingredient', backref=db.backref('video_ingredients', lazy=True))


class Tag(db.Model):
    __tablename__ = 'tags'
    tag_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

class VideoTag(db.Model):
    __tablename__ = 'video_tags'
    video_id = db.Column(db.Integer, db.ForeignKey('videos.video_id'), primary_key=True)
    tag_id = db.Column(db.Integer, db.ForeignKey('tags.tag_id'), primary_key=True)
    tag = db.relationship('Tag', backref=db.backref('video_tags', lazy=True))



class Playlist(db.Model):
    __tablename__ = 'playlists'
    playlist_id = db.Column(db.Integer, primary_key=True)
    user_id     = db.Column(db.Integer, db.ForeignKey('users.user_id', ondelete='CASCADE'), nullable=False)
    name        = db.Column(db.String(255), nullable=False)
    created_at  = db.Column(db.DateTime(timezone=True), server_default=func.now(), nullable=False)
    is_private  = db.Column(db.Boolean, default=False)

    # автоматически удалять все PlaylistVideo при удалении плейлиста
    videos = db.relationship(
        'PlaylistVideo',
        back_populates='playlist',
        cascade='all, delete-orphan',
        passive_deletes=True,
        lazy='dynamic'
    )


class PlaylistVideo(db.Model):
    __tablename__ = 'playlist_videos'
    playlist_id = db.Column(
        db.Integer,
        db.ForeignKey('playlists.playlist_id', ondelete='CASCADE'),
        primary_key=True
    )
    video_id = db.Column(
        db.Integer,
        db.ForeignKey('videos.video_id', ondelete='CASCADE'),
        primary_key=True
    )
    added_at = db.Column(
        db.DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )
    position = db.Column(db.Integer, nullable=False, default=0)

    # связь назад в Playlist
    playlist = db.relationship(
        'Playlist',
        back_populates='videos',
        passive_deletes=True
    )
    # и (опционально) в Video, если вам удобно
    video = db.relationship(
        'Video',
        back_populates='playlists',
        passive_deletes=True
    )
class VideoLike(db.Model):
    __tablename__ = 'video_likes'
    user_id = db.Column(
        db.Integer,
        db.ForeignKey('users.user_id', ondelete='CASCADE'),
        primary_key=True
    )
    video_id = db.Column(
        db.Integer,
        db.ForeignKey('videos.video_id', ondelete='CASCADE'),
        primary_key=True
    )
    like_type = db.Column(db.SmallInteger, nullable=False)  # 1 для лайка, -1 для дизлайка

class Subscription(db.Model):
    __tablename__ = 'subscriptions'
    subscriber_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), primary_key=True)
    subscribed_to_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), primary_key=True)
    subscribed_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class CommentLike(db.Model):
    __tablename__ = 'comment_likes'
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), primary_key=True)
    comment_id = db.Column(db.Integer, db.ForeignKey('comments.comment_id'), primary_key=True)
    liked_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class ViewHistory(db.Model):
    __tablename__ = 'view_history'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey('users.user_id', ondelete='CASCADE'),
        nullable=False
    )
    video_id = db.Column(
        db.Integer,
        db.ForeignKey('videos.video_id', ondelete='CASCADE'),
        nullable=False
    )
    viewed_at = db.Column(
        db.DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )
    



class Notification(db.Model):
    __tablename__ = 'notifications'
    notification_id = db.Column(db.Integer, primary_key=True)

    recipient_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    actor_id     = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=True)

    verb         = db.Column(
        Enum('uploaded_video', 'reply_comment', 'subscribed', name='notif_verbs'),
        nullable=False
    )
    target_video_id = db.Column(
        db.Integer,
        db.ForeignKey('videos.video_id', ondelete='CASCADE'),
        nullable=True
    )
    target_comment_id = db.Column(
    db.Integer,
    db.ForeignKey('comments.comment_id', ondelete='CASCADE'),
    nullable=True
)


    created_at = db.Column(
        db.DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )
    is_read    = db.Column(db.Boolean, default=False)
    is_hidden = db.Column(db.Boolean, default=False)

    # Явно связываем обе связи на User
    recipient = db.relationship(
        'User',
        foreign_keys=[recipient_id],
        back_populates='received_notifications'
    )
    actor = db.relationship(
        'User',
        foreign_keys=[actor_id],
        back_populates='sent_notifications'
    )

    video = db.relationship(
        'Video',
        foreign_keys=[target_video_id],
        passive_deletes=True
    )
    comment = db.relationship('Comment', foreign_keys=[target_comment_id],passive_deletes=True)

class Post(db.Model):
    __tablename__ = 'posts'
    post_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    content = db.Column(db.Text)
    image_url = db.Column(db.String(255))
    created_at = db.Column(
        db.DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )
    is_poll = db.Column(db.Boolean, default=False)
    is_banned = db.Column(db.Boolean, default=False, nullable=False)
    poll_options = db.relationship('PollOption', backref='post', lazy='dynamic')

class PollOption(db.Model):
    __tablename__ = 'poll_options'
    option_id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('posts.post_id'), nullable=False)
    option_text = db.Column(db.String(255), nullable=False)

    votes = db.relationship('Vote', backref='poll_option', lazy='dynamic')

class Vote(db.Model):
    __tablename__ = 'votes'
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), primary_key=True)
    option_id = db.Column(db.Integer, db.ForeignKey('poll_options.option_id'), primary_key=True)
    voted_at = db.Column(
        db.DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )
class VideoReport(db.Model):
    __tablename__ = 'video_reports'
    report_id   = db.Column(db.Integer, primary_key=True)
    video_id = db.Column(
        db.Integer,
        db.ForeignKey('videos.video_id', ondelete='CASCADE'),
        nullable=False
    )
    reporter_id = db.Column(
        db.Integer,
        db.ForeignKey('users.user_id', ondelete='CASCADE'),
        nullable=False
    )
    reason      = db.Column(db.Text, nullable=False)
    created_at  = db.Column(db.DateTime(timezone=True), server_default=func.now(), nullable=False)
    resolved    = db.Column(db.Boolean, default=False, nullable=False)

    video = db.relationship(
        'Video',
        backref=backref('reports',
                       cascade='all, delete-orphan',
                       passive_deletes=True),
        lazy=True
    )
    reporter = db.relationship(
        'User',
        backref=backref('reports_made',
                       cascade='all, delete-orphan',
                       passive_deletes=True),
        lazy=True
    )
class VideoAppeal(db.Model):
    __tablename__ = 'video_appeals'
    appeal_id = db.Column(db.Integer, primary_key=True)
    video_id = db.Column(db.Integer, db.ForeignKey('videos.video_id', ondelete='CASCADE'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id', ondelete='CASCADE'), nullable=False)
    reason = db.Column(db.Text, nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )
    resolved = db.Column(db.Boolean, default=False, nullable=False)

    video = db.relationship('Video', backref='appeals', lazy=True)
    user = db.relationship('User', backref='appeals_made', lazy=True)
