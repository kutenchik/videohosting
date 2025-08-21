# utils.py
import subprocess
import json
import os
import uuid

def get_video_duration(video_path):
    """
    Возвращает длительность видеопотока (в секундах) с помощью ffprobe.
    """
    cmd = [
        'ffprobe',
        '-v', 'error',
        '-select_streams', 'v:0',
        '-show_entries', 'stream=duration',
        '-of', 'default=noprint_wrappers=1:nokey=1',
        video_path
    ]
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                universal_newlines=True, check=True)
        duration_str = result.stdout.strip()
        return float(duration_str) if duration_str else None
    except Exception as e:
        print(f"Ошибка получения длительности: {e}")
        return None
def generate_random_filename(directory, extension):
    """
    Генерирует случайное имя файла с указанным расширением.
    Если файл с таким именем уже существует в заданной директории,
    добавляет суффикс '_1', '_2' и т.д.
    """
    # Получаем базовую случайную строку
    base = uuid.uuid4().hex
    filename = base + extension
    full_path = os.path.join(directory, filename)
    counter = 1
    # Пока файл существует – добавляем суффикс
    while os.path.exists(full_path):
        filename = f"{base}_{counter}{extension}"
        full_path = os.path.join(directory, filename)
        counter += 1
    return filename
def get_video_resolution(video_path):
    """
    Возвращает высоту (в пикселях) видеопотока из файла video_path.
    Требуется, чтобы на сервере был установлен ffprobe.
    """
    cmd = [
        'ffprobe',
        '-v', 'error',
        '-select_streams', 'v:0',
        '-show_entries', 'stream=height',
        '-of', 'json',
        video_path
    ]
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, check=True)
        info = json.loads(result.stdout)
        height = info['streams'][0]['height']
        return height
    except Exception as e:
        print(f"Ошибка получения разрешения: {e}")
        return None

def get_target_qualities(original_height):
    """
    Определяет список целевых качеств на основании оригинального качества.
    Примеры:
      - Если оригинал >= 1440, возвращаем: [1080, 720, 480, 360, 240, 144]
      - Если оригинал >= 1080, возвращаем: [720, 480, 360, 240, 144]
      - Если оригинал >= 720, возвращаем: [480, 360, 240, 144]
      - Иначе, вернем пустой список.
    """
    if original_height is None:
        return []
    if original_height >= 2160:
        return [1440, 1080, 720, 480, 360, 240, 144]
    elif original_height >= 1440:
        return [1080, 720, 480, 360, 240, 144]
    elif original_height >= 1080:
        return [720, 480, 360, 240, 144]
    elif original_height >= 720:
        return [480, 360, 240, 144]
    elif original_height >= 480:
        return [360, 240, 144]
    elif original_height >= 360:
        return [240, 144]
    else:
        return []

def generate_video_variants(original_path, output_dir, target_qualities):
    """
    Для каждого качества из target_qualities генерирует видео с указанным вертикальным разрешением.
    Возвращает словарь, где ключ — качество, значение — путь к сгенерированному файлу.
    
    Пример использования:
      target_qualities = [720, 480, 360, 240, 144]
    """
    results = {}
    base_filename = os.path.splitext(os.path.basename(original_path))[0]
    for quality in target_qualities:
        output_filename = f"{base_filename}_{quality}p.mp4"
        output_path = os.path.join(output_dir, output_filename)
        # Команда для FFmpeg:
        cmd = [
            'ffmpeg', '-y',
            '-i', original_path,
            '-vf', f"scale=-2:{quality}",
            '-c:v', 'libx264',
            '-preset', 'medium',
            '-crf', '23',
            output_path
        ]

        try:
            subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            results[quality] = output_filename  # сохраняем только имя файла (или относительный путь)
        except subprocess.CalledProcessError as e:
            print(f"Ошибка при генерации {quality}p: {e.stderr}")
    return results
# def extract_audio(video_path, output_audio_path):
#     """
#     Извлекает аудио из видео с помощью FFmpeg и сохраняет его в output_audio_path (например, .wav файл).
#     """
#     cmd = [
#         "ffmpeg", "-y",  # -y для перезаписи
#         "-i", video_path,
#         "-vn",  # не сохранять видео
#         "-acodec", "pcm_s16le",  # кодек для WAV (16-bit PCM)
#         "-ar", "16000",  # частота дискретизации 16 kHz, рекомендовано для распознавания речи
#         "-ac", "1",  # моно
#         output_audio_path
#     ]
#     try:
#         subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
#         return True
#     except subprocess.CalledProcessError as e:
#         print("Ошибка при извлечении аудио:", e.stderr.decode())
#         return False
# def generate_subtitles(audio_path, output_vtt_path, language_code="ru-RU"):
#     """
#     Генерирует файл субтитров в формате WebVTT, используя Google Cloud Speech.
#     Параметры:
#       audio_path: путь к аудио файлу (WAV)
#       output_vtt_path: куда сохранить VTT файл
#       language_code: код языка для распознавания (например, "ru-RU")
#     """
#     client = speech.SpeechClient()
#     with io.open(audio_path, "rb") as audio_file:
#         content = audio_file.read()
#     audio = speech.RecognitionAudio(content=content)

#     config = speech.RecognitionConfig(
#         encoding=speech.RecognitionConfig.AudioEncoding.LINEAR16,
#         sample_rate_hertz=16000,
#         language_code=language_code,
#         enable_automatic_punctuation=True
#     )

#     # Отправляем аудио на распознавание.
#     operation = client.long_running_recognize(config=config, audio=audio)
#     response = operation.result(timeout=90)

#     # Формируем WebVTT контент.
#     vtt_lines = ["WEBVTT", ""]
#     index = 1
#     # В ответе получаем несколько результатов. В простейшем случае один результат (речь непрерывная)
#     for result in response.results:
#         alternative = result.alternatives[0]
#         # Для упрощения примера берем тайминг начала и конца первого слова
#         if alternative.words:
#             start_time = alternative.words[0].start_time.total_seconds()
#             end_time = alternative.words[-1].end_time.total_seconds()
#         else:
#             start_time, end_time = 0, 0
        
#         # Преобразуем секунды в формат hh:mm:ss,ms
#         def format_timestamp(time_sec):
#             hours = int(time_sec // 3600)
#             minutes = int((time_sec % 3600) // 60)
#             seconds = int(time_sec % 60)
#             milliseconds = int((time_sec - int(time_sec)) * 1000)
#             return f"{hours:02d}:{minutes:02d}:{seconds:02d}.{milliseconds:03d}"
        
#         start_str = format_timestamp(start_time)
#         end_str = format_timestamp(end_time)
#         vtt_lines.append(f"{index}")
#         vtt_lines.append(f"{start_str} --> {end_str}")
#         vtt_lines.append(alternative.transcript)
#         vtt_lines.append("")  # пустая строка между блоками
#         index += 1

#     # Записываем файл
#     with open(output_vtt_path, "w", encoding="utf-8") as f:
#         f.write("\n".join(vtt_lines))