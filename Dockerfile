FROM oqs-python
RUN . /home/oqs/venv/bin/activate && pip install cryptography pytest psutil jupyter ipykernel matplotlib