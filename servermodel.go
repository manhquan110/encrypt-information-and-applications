package main

import (
	"fmt"
	"html/template"
	"io/ioutil"
	//"net"
	"net/http"
	"os"
	//"os/exec"
	"os/signal"
	"time"
	//"path/filepath"
	//"runtime"
	//"strings"
)

type Server struct {
	dataBase DataBase
	cookie   *SecureCookie
}

func (s *Server) setSession(email string, response http.ResponseWriter) {
	value := map[string]string{
		"email": email,
	}
	if encoded, err := s.cookie.Encode("session", value); err == nil {
		cookie := &http.Cookie{
			Name:  "session",
			Value: encoded,
			Path:  "/",
		}
		http.SetCookie(response, cookie)
	}
}

func (s *Server) getEmailUser(request *http.Request) string {
	var emailUser string
	if cookie, err := request.Cookie("session"); err == nil {
		cookieValue := make(map[string]string)
		if err = s.cookie.Decode("session", cookie.Value, &cookieValue); err == nil {
			emailUser = cookieValue["email"]
		}
	}
	return emailUser
}

func (s *Server) clearSession(response http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:   "session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	}
	http.SetCookie(response, cookie)
}

func (s *Server) indexHandler(w http.ResponseWriter, r *http.Request) {
	index := template.Must(template.ParseFiles(
		"./template/index.html",
	))
	index.Execute(w, nil)
}

func (s *Server) registerHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	newUser := User{
		Name:        r.FormValue("name"),
		Email:       r.FormValue("email"),
		Address:     r.FormValue("address"),
		PhoneNumber: r.FormValue("phonenumber"),
		DateOfBirth: r.FormValue("dob"),
	}
	s.dataBase.addUser(newUser, r.FormValue("password"), r.FormValue("keylength"))
	s.setSession(newUser.Email, w)
	http.Redirect(w, r, "/dashboard", 301)
}

func (s *Server) loginHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	email := r.FormValue("email")
	pass := r.FormValue("password")

	redirect := "/"
	if email != "" && s.dataBase.isVaidUser(email, pass) {
		s.setSession(email, w)
		redirect = "/dashboard"
	}
	http.Redirect(w, r, redirect, 302)
}

func (s *Server) dashboardHandler(w http.ResponseWriter, r *http.Request) {
	userEmail := s.getEmailUser(r)
	if userEmail != "" {
		dashboard := template.Must(template.ParseFiles(
			"./template/dashboard.html",
		))
		dashboard.Execute(w, nil)
	} else {
		http.Redirect(w, r, "/", 302)
	}
}

func (s *Server) logoutHandler(w http.ResponseWriter, r *http.Request) {
	s.clearSession(w)
	http.Redirect(w, r, "/", 302)
}

func (s *Server) shutdown() error {
	return s.dataBase.save()

}

func (s *Server) run() error {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)
	go func() {
		for _ = range signalChan {
			fmt.Println("\nReceived an interrupt, stopping services...\n")
			s.shutdown()
			os.Exit(1)
		}
	}()
	s.cookie = New(GenerateRandomKey(64), GenerateRandomKey(32))

	return server.dataBase.load("./DataBase.xml")
}

func (s *Server) dashboardExport(w http.ResponseWriter, r *http.Request) {
	userEmail := s.getEmailUser(r)
	if userEmail != "" {
		userExport := s.dataBase.getUserXML(userEmail)
		w.Header().Set("Content-Type", "application/xml")
		w.Header().Add("Content-Disposition", "attachment;filename="+userEmail+".xml")
		w.Write(userExport)
	} else {
		http.Redirect(w, r, "/", 302)
	}
}

func (s *Server) dashboardImport(w http.ResponseWriter, r *http.Request) {
	userEmail := s.getEmailUser(r)
	if userEmail != "" {
		r.ParseMultipartForm(32 << 20)

		file, _, err := r.FormFile("userimport")
		if err != nil {
			fmt.Println(err)
			return
		}
		defer file.Close()
		bytesRead, _ := ioutil.ReadAll(file)
		s.dataBase.updateInfoImport(userEmail, bytesRead)
	} else {
		http.Redirect(w, r, "/", 302)
	}

	http.Redirect(w, r, "/dashboard", 302)

}

func (s *Server) dashboardUpdate(w http.ResponseWriter, r *http.Request) {
	userEmail := s.getEmailUser(r)
	r.ParseForm()
	pass := r.FormValue("oldpassword")
	if userEmail != "" && s.dataBase.isVaidUser(userEmail, pass) {
		newUser := User{
			Name:        r.FormValue("name"),
			Email:       r.FormValue("email"),
			Address:     r.FormValue("address"),
			PhoneNumber: r.FormValue("phonenumber"),
			DateOfBirth: r.FormValue("dob"),
		}
		s.dataBase.updateInfo(newUser, r.FormValue("password"))
	} else {
		http.Redirect(w, r, "/", 302)
	}

}

func (s *Server) dashboardSign(w http.ResponseWriter, r *http.Request) {
	userEmail := s.getEmailUser(r)
	if userEmail != "" {
		r.ParseMultipartForm(32 << 20)

		file, handle, err := r.FormFile("usersign")
		if err != nil {
			fmt.Println(err)
			return
		}
		defer file.Close()

		bytesRead, _ := ioutil.ReadAll(file)
		user := s.dataBase.get(userEmail)
		userSign, _ := user.Sign(bytesRead)
		//return file
		w.Header().Set("Content-Type", "application/text")
		w.Header().Add("Content-Disposition", "attachment;filename="+handle.Filename+".sig")
		w.Write(userSign)
	} else {
		http.Redirect(w, r, "/", 302)
	}
}

func (s *Server) dashboardVerify(w http.ResponseWriter, r *http.Request) {
	userEmail := s.getEmailUser(r)
	if userEmail != "" {
		r.ParseMultipartForm(32 << 20)

		file, _, errfile := r.FormFile("fileuserverify")
		filesig, _, errsig := r.FormFile("siguserverify")
		if errfile != nil && errsig != nil {
			fmt.Println(errfile, errsig)
			return
		}
		defer file.Close()

		message, _ := ioutil.ReadAll(file)
		sig, _ := ioutil.ReadAll(filesig)
		//user := s.dataBase.get(userEmail)
		var verify error
		for _, user := range s.dataBase.UsersData.Data {
			verify = user.Verify(message, sig)
			if verify == nil {
				break
			}
		}
		if verify == nil {
			fmt.Fprintln(w, "Success!!!")
		} else {
			fmt.Fprintln(w, "Wrong!!!")
		}
		time.Sleep(3 * time.Second)
		http.Redirect(w, r, "/dashboard", 302)
	} else {
		http.Redirect(w, r, "/", 302)
	}

}

func (s *Server) dashboardEncypt(w http.ResponseWriter, r *http.Request) {
	userEmail := s.getEmailUser(r)
	if userEmail != "" {
		r.ParseMultipartForm(32 << 20)

		file, handle, err := r.FormFile("userencrypt")
		if err != nil {
			fmt.Println(err)
			return
		}
		defer file.Close()

		bytesRead, _ := ioutil.ReadAll(file)
		user := s.dataBase.get(userEmail)

		fileEncrypt, err := user.AESencrypt(bytesRead)
		fmt.Println(fileEncrypt, err)

		//return file
		w.Header().Set("Content-Type", "application/text")
		w.Header().Add("Content-Disposition", "attachment;filename="+handle.Filename)
		w.Write(fileEncrypt)
	} else {
		http.Redirect(w, r, "/", 302)
	}
}

func (s *Server) dashboardDecrypt(w http.ResponseWriter, r *http.Request) {
	userEmail := s.getEmailUser(r)
	if userEmail != "" {
		r.ParseMultipartForm(32 << 20)

		file, handle, err := r.FormFile("userdecrypt")
		if err != nil {
			fmt.Println(err)
			return
		}
		defer file.Close()

		bytesRead, _ := ioutil.ReadAll(file)
		user := s.dataBase.get(userEmail)

		filedecrypt, err := user.AESdecrypt(bytesRead)
		fmt.Println(filedecrypt, err)

		//return file
		w.Header().Set("Content-Type", "application/text")
		w.Header().Add("Content-Disposition", "attachment;filename="+handle.Filename)
		w.Write(filedecrypt)
	} else {
		http.Redirect(w, r, "/", 302)
	}

}
