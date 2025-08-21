from flask import Blueprint, render_template, redirect, url_for, request, flash, abort
from flask_login import login_required, current_user
from functools import wraps
from myapp.models import User, Video, Comment, Post, VideoReport,VideoAppeal
from myapp import db

admin_bp = Blueprint('admin', __name__, url_prefix='/admin', template_folder='templates/admin')

def admin_required(f):
    @wraps(f)
    def decorated_view(*args, **kwargs):
        if not current_user.is_authenticated or not getattr(current_user, 'is_admin', False):
            abort(403)
        return f(*args, **kwargs)
    return decorated_view

@admin_bp.route('/')
@login_required
@admin_required
def dashboard():
    stats = {
        'users':    User.query.count(),
        'videos':   Video.query.count(),
        'comments': Comment.query.count(),
        'posts':    Post.query.count()
    }
    return render_template('admin/dashboard.html', stats=stats)

# --- Пользователи ---
@admin_bp.route('/users')
@login_required
@admin_required
def list_users():
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin/users.html', users=users)

@admin_bp.route('/users/<int:user_id>/ban', methods=['POST'])
@login_required
@admin_required
def ban_user(user_id):
    u = User.query.get_or_404(user_id)
    u.is_banned = True
    db.session.commit()
    flash(f'Пользователь {u.username} забанен.', 'success')
    return redirect(url_for('admin.list_users'))

@admin_bp.route('/users/<int:user_id>/unban', methods=['POST'])
@login_required
@admin_required
def unban_user(user_id):
    u = User.query.get_or_404(user_id)
    u.is_banned = False
    db.session.commit()
    flash(f'Пользователь {u.username} разбанен.', 'success')
    return redirect(url_for('admin.list_users'))

@admin_bp.route('/users/<int:user_id>/promote', methods=['POST'])
@login_required
@admin_required
def promote_user(user_id):
    u = User.query.get_or_404(user_id)
    u.is_admin = True
    db.session.commit()
    flash(f'Пользователь {u.username} теперь админ.', 'success')
    return redirect(url_for('admin.list_users'))

@admin_bp.route('/users/<int:user_id>/demote', methods=['POST'])
@login_required
@admin_required
def demote_user(user_id):
    u = User.query.get_or_404(user_id)
    u.is_admin = False
    db.session.commit()
    flash(f'Пользователь {u.username} теперь обычный.', 'success')
    return redirect(url_for('admin.list_users'))

# --- Видео ---
@admin_bp.route('/videos')
@login_required
@admin_required
def list_videos():
    videos = Video.query.order_by(Video.upload_date.desc()).all()
    return render_template('admin/videos.html', videos=videos)

@admin_bp.route('/videos/<int:video_id>/ban', methods=['POST'])
@login_required
@admin_required
def ban_video(video_id):
    v = Video.query.get_or_404(video_id)
    v.is_banned = True
    db.session.commit()
    flash('Видео забанено.', 'success')
    return redirect(url_for('admin.list_videos'))

@admin_bp.route('/videos/<int:video_id>/unban', methods=['POST'])
@login_required
@admin_required
def unban_video(video_id):
    v = Video.query.get_or_404(video_id)
    v.is_banned = False
    db.session.commit()
    flash('Видео разбанено.', 'success')
    return redirect(url_for('admin.list_videos'))

# --- Комментарии ---
@admin_bp.route('/comments')
@login_required
@admin_required
def list_comments():
    comments = Comment.query.order_by(Comment.created_at.desc()).all()
    return render_template('admin/comments.html', comments=comments)

@admin_bp.route('/comments/<int:comment_id>/ban', methods=['POST'])
@login_required
@admin_required
def ban_comment(comment_id):
    c = Comment.query.get_or_404(comment_id)
    c.is_banned = True
    db.session.commit()
    flash('Комментарий забанен.', 'success')
    return redirect(url_for('admin.list_comments'))

@admin_bp.route('/comments/<int:comment_id>/unban', methods=['POST'])
@login_required
@admin_required
def unban_comment(comment_id):
    c = Comment.query.get_or_404(comment_id)
    c.is_banned = False
    db.session.commit()
    flash('Комментарий разбанен.', 'success')
    return redirect(url_for('admin.list_comments'))

# --- Посты ---
@admin_bp.route('/posts')
@login_required
@admin_required
def list_posts():
    posts = Post.query.order_by(Post.created_at.desc()).all()
    return render_template('admin/posts.html', posts=posts)

@admin_bp.route('/posts/<int:post_id>/ban', methods=['POST'])
@login_required
@admin_required
def ban_post(post_id):
    p = Post.query.get_or_404(post_id)
    p.is_banned = True
    db.session.commit()
    flash('Пост забанен.', 'success')
    return redirect(url_for('admin.list_posts'))

@admin_bp.route('/posts/<int:post_id>/unban', methods=['POST'])
@login_required
@admin_required
def unban_post(post_id):
    p = Post.query.get_or_404(post_id)
    p.is_banned = False
    db.session.commit()
    flash('Пост разбанен.', 'success')
    return redirect(url_for('admin.list_posts'))
@admin_bp.route('/reports')
@login_required
@admin_required
def list_reports():
    reports = VideoReport.query.order_by(VideoReport.created_at.desc()).all()
    return render_template('admin/reports.html', reports=reports)

@admin_bp.route('/reports/<int:report_id>/ban', methods=['POST'])
@login_required
@admin_required
def ban_reported_video(report_id):
    rpt = VideoReport.query.get_or_404(report_id)
    v   = rpt.video
    v.is_banned = True
    rpt.resolved = True
    db.session.commit()
    flash(f'Видео "{v.title}" забанено, жалоба помечена как обработанная.', 'success')
    return redirect(url_for('admin.list_reports'))

@admin_bp.route('/reports/<int:report_id>/ignore', methods=['POST'])
@login_required
@admin_required
def ignore_report(report_id):
    rpt = VideoReport.query.get_or_404(report_id)
    rpt.resolved = True
    db.session.commit()
    flash('Жалоба помечена как обработанная без бана видео.', 'info')
    return redirect(url_for('admin.list_reports'))

@admin_bp.route('/appeals')
@login_required
@admin_required
def view_appeals():
    appeals = VideoAppeal.query.filter_by(resolved=False).order_by(VideoAppeal.created_at.desc()).all()
    return render_template('admin/appeals.html', appeals=appeals)

@admin_bp.route('/appeals/<int:appeal_id>/unblock', methods=['POST'])
@login_required
@admin_required
def unblock_video(appeal_id):
    appeal = VideoAppeal.query.get_or_404(appeal_id)
    video = appeal.video
    video.is_banned = False
    appeal.resolved = True
    db.session.commit()
    flash(f'Видео "{video.title}" разблокировано', 'success')
    return redirect(url_for('admin.view_appeals'))
