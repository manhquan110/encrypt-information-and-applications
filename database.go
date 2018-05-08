package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"encoding/xml"
	"errors"
	//"fmt"
	"strconv"
	"sync"
	"time"
)

type DataBase struct {
	EmailID   map[string]User
	UsersData Users
	mutex     sync.Mutex
}

func (s *DataBase) load(path string) error {
	if err := s.UsersData.load(path); err != nil {
		return err
	}
	s.updateEmailID()
	return nil
}

func (s *DataBase) updateEmailID() {
	s.EmailID = make(map[string]User)
	for _, p := range s.UsersData.Data {
		s.EmailID[p.Email] = p
	}
}

func (s *DataBase) save() error {
	if err := s.UsersData.save(); err != nil {
		return err
	}
	return nil
}

func (s *DataBase) addUser(newuser User, password, keyLen string) {
	length, _ := strconv.ParseInt(keyLen, 10, 32)
	pub, pri, _ := keyGenOption(int(length))
	s.addUserAsInfo(newuser.Email, newuser.Name, newuser.Address, newuser.PhoneNumber, newuser.DateOfBirth, password, *pub, *pri)
}

func (s *DataBase) addUserAsInfo(email, name, address, phonenumber, dob, pass, public, private string) error {
	s.mutex.Lock()
	if s.get(email) != (User{}) {
		return errors.New("Email ALREADY register!!!")
	}
	salt := time.Now().Format(time.RFC850)
	hash := sha1.New()
	hash.Write([]byte(pass + salt))
	hashbytes := hash.Sum(nil)
	password := hex.EncodeToString(hashbytes[:])

	userRecord := User{Email: email, Name: name, Address: address, PhoneNumber: phonenumber, DateOfBirth: dob, PassSaltHash: password, Salt: salt, RSApublic: public, RSAprivate: private}

	s.EmailID[email] = userRecord
	s.UsersData.addUser(userRecord)
	s.mutex.Unlock()
	return nil
}

func (s *DataBase) isVaidUser(email, pass string) bool {
	s.updateEmailID()
	checkUser := s.get(email)
	salt := checkUser.Salt
	hash := sha1.New()
	hash.Write([]byte(pass + salt))
	password := hash.Sum(nil)

	toCompare, _ := hex.DecodeString(checkUser.PassSaltHash)

	return (bytes.Compare(toCompare, password) == 0)
}

func (s *DataBase) get(email string) User {
	if val, ok := s.EmailID[email]; ok {
		return val
	}
	return User{}
}

func (s *DataBase) getUserXML(email string) []byte {
	getUser := s.get(email)
	xmlmarshal, _ := xml.MarshalIndent(getUser, "", " ")

	return xmlmarshal
}

func (s *DataBase) updateInfo(newuser User, password string) {
	checkUser := s.get(newuser.Email)
	salt := checkUser.Salt
	hash := sha1.New()
	hash.Write([]byte(password + salt))
	hashbytes := hash.Sum(nil)
	pass := hex.EncodeToString(hashbytes[:])
	userRecord := User{Email: checkUser.Email, Name: newuser.Name,
		Address: newuser.Address, PhoneNumber: newuser.PhoneNumber, DateOfBirth: newuser.PhoneNumber,
		PassSaltHash: pass, Salt: salt, RSApublic: checkUser.RSApublic, RSAprivate: checkUser.RSAprivate}
	s.UsersData.update(userRecord)
	s.updateEmailID()
}

func (s *DataBase) updateInfoImport(email string, data []byte) error {
	var user User
	xml.Unmarshal(data, &user)
	if email != user.Email {
		return errors.New("Khac email!, Cap khoa khong thuoc chu so huu!")
	}
	s.UsersData.update(user)
	s.updateEmailID()
	return nil
}
