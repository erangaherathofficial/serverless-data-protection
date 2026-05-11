FROM public.ecr.aws/lambda/python:3.13@sha256:67b32eb858d2124326e3887fa825a0db934cbbd22f2b0ce489ee1def49020cfe

COPY requirements.txt ${LAMBDA_TASK_ROOT}/
RUN pip install --no-cache-dir -r ${LAMBDA_TASK_ROOT}/requirements.txt

# Large spaCy model — best static-feature NER for accurate PERSON/LOCATION
# detection on isolated strings without the transformer's cold-start cost.
# Pinned to a specific wheel so image rebuilds are reproducible.
RUN pip install --no-cache-dir \
    https://github.com/explosion/spacy-models/releases/download/en_core_web_lg-3.8.0/en_core_web_lg-3.8.0-py3-none-any.whl

COPY src/ ${LAMBDA_TASK_ROOT}/src/
COPY policies/ ${LAMBDA_TASK_ROOT}/policies/

CMD ["src.lambda_handler.handler"]
