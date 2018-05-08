package main

import (
	"encoding/xml"
	"io"
	"io/ioutil"
	"os"
)

// if variable name starts with small cap
// for example : "tape" instead of "Tape"
// the final value will not appear in XML
type User struct {
	XMLName      xml.Name `xml:"user"`
	Email        string   `xml:"email"`
	Name         string   `xml:"name"`
	Address      string   `xml:"address"`
	PhoneNumber  string   `xml:"phonenumber"`
	DateOfBirth  string   `xml:"dateofbirth"`
	PassSaltHash string   `xml:"password"`
	Salt         string   `xml:"salt"`
	RSApublic    string   `xml:"RSApublic"`
	RSAprivate   string   `xml:"RSAprivate"`
}

func (u *User) update(up User) {
	*u = up
}

type Users struct {
	XMLName xml.Name `xml:"database"`
	Data    []User   `xml:"user"`
}

func (s *Users) load(path string) error {
	database, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer database.Close()
	XMLdatabase, _ := ioutil.ReadAll(database)
	if err := xml.Unmarshal(XMLdatabase, &s); err != nil {
		return err
	}

	return nil
}

func (s *Users) update(user User) {
	for i := range s.Data {
		if s.Data[i].Email == user.Email {
			s.Data[i].update(user)
			return
		}
	}
}

func (s *Users) save() error {
	// everything ok now, write to file.
	filename := "DataBase.xml"
	file, _ := os.Create(filename)
	defer file.Close()

	xmlWriter := io.Writer(file)

	enc := xml.NewEncoder(xmlWriter)
	enc.Indent("  ", "    ")
	if err := enc.Encode(s); err != nil {
		return err
	}
	return nil
}

func (s *Users) addUser(newUser User) {
	s.Data = append(s.Data, newUser)
}
