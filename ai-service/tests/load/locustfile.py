"""
Locust Load Testing for AI Microservice
Tests chat, DTE validation, and project matching endpoints
"""

from locust import HttpUser, task, between
import random

class AIServiceUser(HttpUser):
    """
    Simulates user behavior for AI microservice endpoints
    """
    wait_time = between(1, 3)  # Wait 1-3 seconds between requests

    def on_start(self):
        """Setup authentication"""
        self.headers = {
            "Authorization": "Bearer your-api-key-here",
            "Content-Type": "application/json"
        }

        # Sample test data
        self.chat_messages = [
            "¿Cómo genero un DTE 33?",
            "¿Qué es una boleta de honorarios?",
            "¿Cómo configuro el CAF?",
            "Explícame el proceso de facturación electrónica",
            "¿Cuáles son los tipos de DTE disponibles?"
        ]

        self.dte_types = ["33", "34", "52", "56", "61"]

        self.partner_vats = [
            "76.123.456-7",
            "12.345.678-9",
            "98.765.432-1"
        ]

    @task(3)
    def chat_message(self):
        """Test chat endpoint (higher frequency)"""
        message = random.choice(self.chat_messages)

        self.client.post(
            "/api/chat/message",
            json={
                "session_id": f"load-test-{random.randint(1, 10)}",
                "message": message
            },
            headers=self.headers,
            name="/api/chat/message"
        )

    @task(1)
    def dte_validation(self):
        """Test DTE validation (lower frequency)"""
        self.client.post(
            "/api/ai/validate",
            json={
                "dte_type": random.choice(self.dte_types),
                "partner_vat": random.choice(self.partner_vats),
                "amount": random.randint(10000, 1000000),
                "items": [
                    {
                        "name": "Item 1",
                        "quantity": random.randint(1, 10),
                        "price": random.randint(1000, 50000)
                    }
                ]
            },
            headers=self.headers,
            name="/api/ai/validate"
        )

    @task(1)
    def project_matching(self):
        """Test project matching endpoint"""
        self.client.post(
            "/api/ai/analytics/suggest_project",
            json={
                "invoice_description": "Servicio de consultoría",
                "partner_name": "Cliente Test",
                "amount": random.randint(100000, 5000000)
            },
            headers=self.headers,
            name="/api/ai/analytics/suggest_project"
        )

    @task(2)
    def chat_stream(self):
        """Test streaming chat endpoint"""
        message = random.choice(self.chat_messages)

        with self.client.post(
            "/api/chat/message/stream",
            json={
                "session_id": f"load-test-stream-{random.randint(1, 5)}",
                "message": message
            },
            headers=self.headers,
            name="/api/chat/message/stream",
            stream=True,
            catch_response=True
        ) as response:
            if response.status_code == 200:
                # Consume stream
                for chunk in response.iter_content(chunk_size=1024):
                    if chunk:
                        pass  # Process chunk
                response.success()
            else:
                response.failure(f"Status code: {response.status_code}")

    @task(1)
    def health_check(self):
        """Test health endpoint (low frequency)"""
        self.client.get(
            "/health",
            name="/health"
        )
