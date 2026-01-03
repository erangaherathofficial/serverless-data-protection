FROM public.ecr.aws/lambda/python:3.12

# Copy requirements
COPY requirements.txt ${LAMBDA_TASK_ROOT}/

# Install dependencies
RUN pip install --no-cache-dir -r ${LAMBDA_TASK_ROOT}/requirements.txt

# Download spacy model for Presidio (using small model for faster Lambda cold starts)
RUN python -m spacy download en_core_web_sm

# Copy application code
COPY src/ ${LAMBDA_TASK_ROOT}/src/
COPY policies/ ${LAMBDA_TASK_ROOT}/policies/

# Ensure proper permissions for Lambda
RUN chmod -R 755 ${LAMBDA_TASK_ROOT}/src/ && \
    chmod -R 755 ${LAMBDA_TASK_ROOT}/policies/

# Set the handler
CMD ["src.lambda_handler.handler"]
