./mvnw spring-boot:run

POST http://localhost:8080/api/auth/signup

{
    "username": "testuser",
    "email": "testuser@example.com",
    "password": "Test@123",
    "role": "ROLE_USER"
}





POST http://localhost:8080/api/auth/signin

{
    "username": "testuser",
    "password": "Test@123"
}
