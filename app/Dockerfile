FROM python:3.11

WORKDIR /code

COPY ./requirements.txt /code/requirements.txt

ENV SECRET_KEY="09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ENV ALGORITHM="HS256"
ENV ACCESS_TOKEN_EXPIRE_MINUTES=5
ENV SECRET_KEY_FERNET="uybQyxqKusKRYUImb6nyt8TdB6O_uc9OZcv9bkeLQ18="
ENV LOCKOUT_TIME_MIN=10
ENV MAX_ATTEMPTS=5
ENV CLOUDINARY_CLOUD_NAME=ecommerceonestore
ENV CLOUDINARY_API_KEY=886259588677685
ENV CLOUDINARY_API_SECRET=egfHwEAr8xhjEje0mEI-BWY5ggI

RUN pip install --no-cache-dir --upgrade -r /code/requirements.txt

COPY . /code/app

CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:8066", "-k", "uvicorn.workers.UvicornWorker", "app.api_app:api_app"]