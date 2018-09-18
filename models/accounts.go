package models

import (
	u "faith-core/utils"
	"os"

	"github.com/dgrijalva/jwt-go"
	"github.com/jinzhu/gorm"
	"golang.org/x/crypto/bcrypt"
)

/*
JWT claims struct
*/
type Token struct {
	UserId   uint
	Username string
	jwt.StandardClaims
}

//a struct to rep user account
type Account struct {
	gorm.Model
	Token    string `json:"token";sql:"-"`
	Phone    string `json:"phone"`
	Uuid     string `json:"uuid"`
	Name     string `json:"name"`
	Username string `json:"username"`
}

//Validate incoming user details...
func (account *Account) Validate() (map[string]interface{}, bool) {

	if len(account.Name) < 2 {
		return u.Message(false, "Name is too short"), false
	}

	if account.Uuid == "" {
		return u.Message(false, "Unique id is not provided"), false
	}

	//Email must be unique
	temp := &Account{}

	//check for errors and duplicate emails
	err := GetDB().Table("accounts").Where("phone = ?", account.Phone).First(temp).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return u.Message(false, "Connection error. Please retry"), false
	}
	if temp.Phone != "" {
		return u.Message(false, "Phone already in use by another user."), false
	}

	return u.Message(false, "Requirement passed"), true
}

func (account *Account) Create() map[string]interface{} {

	if resp, ok := account.Validate(); !ok {
		return resp
	}

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(account.Uuid), bcrypt.DefaultCost)
	account.Uuid = string(hashedPassword)

	GetDB().Create(account)

	if account.ID <= 0 {
		return u.Message(false, "Failed to create account, connection error.")
	}

	//Create new JWT token for the newly registered account
	tk := &Token{UserId: account.ID}
	token := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), tk)
	tokenString, _ := token.SignedString([]byte(os.Getenv("token_password")))
	account.Token = tokenString

	account.Uuid = "" //delete password

	response := u.Message(true, "Account has been created")
	response["account"] = account
	return response
}

func Login(phone, uuid string) map[string]interface{} {

	if uuid == "" {
		return u.Message(false, "Missing unique id")
	}

	account := &Account{}
	err := GetDB().Table("accounts").Where("phone = ?", phone).First(account).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			resp := u.Message(true, "User is not registered")
			resp["registered"] = false
			return resp
		}
		return u.Message(false, "Connection error. Please retry")
	}

	err = bcrypt.CompareHashAndPassword([]byte(account.Uuid), []byte(uuid))
	if err != nil && err == bcrypt.ErrMismatchedHashAndPassword { //Password does not match!
		return u.Message(false, "Invalid login credentials.")
	}
	//Worked! Logged In
	account.Uuid = ""

	//Create JWT token
	tk := &Token{UserId: account.ID}
	token := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), tk)
	tokenString, _ := token.SignedString([]byte(os.Getenv("token_password")))
	account.Token = tokenString //Store the token in the response

	resp := u.Message(true, "Logged In")
	resp["account"] = account
	resp["registered"] = true
	return resp
}

func GetUser(u uint) *Account {

	acc := &Account{}
	GetDB().Table("accounts").Where("id = ?", u).First(acc)
	if acc.Phone == "" { //User not found!
		return nil
	}

	acc.Uuid = ""
	return acc
}
