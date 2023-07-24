package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"


	"github.com/stretchr/testify/mock"
)


type MockDB struct {
	mock.Mock
}

func (m *MockDB) Get(dest interface{}, query string, args ...interface{}) error {
	call := m.Called(dest, query, args)
	if call.Error(0) != nil {
		return call.Error(0)
	}
	return nil
}

func (m *MockDB) Select(dest interface{}, query string, args ...interface{}) error {
	call := m.Called(dest, query, args)
	if call.Error(0) != nil {
		return call.Error(0)
	}
	return nil
}

func (m *MockDB) Exec(query string, args ...interface{}) (sql.Result, error) {
	call := m.Called(query, args)
	if call.Error(1) != nil {
		return nil, call.Error(1)
	}
	return call.Get(0).(sql.Result), nil
}

func (m *MockDB) NamedExec(query string, arg interface{}) (sql.Result, error) {
	call := m.Called(query, arg)
	if call.Error(1) != nil {
		return nil, call.Error(1)
	}
	return call.Get(0).(sql.Result), nil
}

func TestLoginHandler(t *testing.T) {
	mockDB := new(MockDB)
	app := &App{DB: mockDB}

	reqBody := bytes.NewBuffer(json.RawMessage(`{
		"username": "user1",
		"password": "password1"
	}`))

	req, err := http.NewRequest("POST", "/login", reqBody)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(app.LoginHandler)

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusCreated {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusCreated)
	}

	expected := `{"token":`
	if rr.Body.String()[:len(expected)] != expected {
		t.Errorf("handler returned unexpected body: got %v want %v", rr.Body.String(), expected)
	}
}

func TestVerifyHandler(t *testing.T) {
	mockDB := new(MockDB)
	app := &App{DB: mockDB}

	token, err := GenerateToken("user1")
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest("GET", "/verify", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	rr := httptest.NewRecorder()

	handler := http.HandlerFunc(app.VerifyHandler)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	expected := "Hello, user1"
	if rr.Body.String() != expected {
		t.Errorf("handler returned unexpected body: got %v want %v", rr.Body.String(), expected)
	}
}

func TestUsersHandler_GET(t *testing.T) {
	// Prepare a test user
	user := User{
		ID:           1,
		Username:     "user1",
		PasswordHash: "password1_hash",
	}
	// Set up a mock database connection
	mockDB := new(MockDB)
	// Set up the mock database to return the test user
	mockDB.On("Select", mock.Anything, mock.Anything).Return(user, nil)
	// Set up the handler
	handler := App{
		DB: mockDB,
	}
	// Create a request
	req, err := http.NewRequest("GET", "/users/1", nil)
	if err != nil {
		t.Fatal(err)
	}
	// Record the response
	rr := httptest.NewRecorder()

	// Call the handler
	handler.ServeHTTP(rr, req)

	// Check the status code
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Check the response body
	expected := `{"id":1,"username":"user1","password_hash":"password1_hash"}`
	if rr.Body.String() != expected {
		t.Errorf("handler returned unexpected body: got %v want %v", rr.Body.String(), expected)
	}
}
