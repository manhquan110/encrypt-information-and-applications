package main

import (
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

func runBrowser(url string) {
	for _, err := net.Listen("tcp", "localhost:8080"); err == nil; _, err = net.Listen("tcp", "localhost:8080") {
	}
	if runtime.GOOS == "windows" {
		cmd := "url.dll,FileProtocolHandler"
		runDll32 := filepath.Join(os.Getenv("SYSTEMROOT"), "System32", "rundll32.exe")
		exec.Command(runDll32, cmd, url).Output()
	} else if runtime.GOOS == "unix" {
		exec.Command("xdg-open", url).Output()
	} else { //macOS
		exec.Command("open", url).Output()
	}
}

var (
	server Server
)

func main() {
	server.run()
	go runBrowser("http://localhost:8080/")
	http.Handle("/css/", http.StripPrefix("/css/", http.FileServer(http.Dir("./template/css"))))
	http.Handle("/js/", http.StripPrefix("/js/", http.FileServer(http.Dir("./template/js"))))
	http.HandleFunc("/", server.indexHandler)
	http.HandleFunc("/reg", server.registerHandler)
	http.HandleFunc("/log", server.loginHandler)
	http.HandleFunc("/logout", server.logoutHandler)
	http.HandleFunc("/dashboard", server.dashboardHandler)
	http.HandleFunc("/dashboard/export", server.dashboardExport)
	http.HandleFunc("/dashboard/import", server.dashboardImport)
	http.HandleFunc("/dashboard/update", server.dashboardUpdate)

	http.HandleFunc("/dashboard/filesign", server.dashboardSign)
	http.HandleFunc("/dashboard/fileverify", server.dashboardVerify)
	http.HandleFunc("/dashboard/fileencrypt", server.dashboardEncypt)
	http.HandleFunc("/dashboard/filedecrypt", server.dashboardDecrypt)
	http.ListenAndServe(":8080", nil)
}
