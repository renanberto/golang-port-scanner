package main

import (
	"fmt"
	"log"
	"net/smtp"
	"time"

	"github.com/anvie/port-scanner"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/scorredoira/email"
	"net/mail"
	"os"
)

// OpenedPorts receive all IPS and PORT associations opened
type OpenedPorts struct {
	IP   string
	PORT []int
}

// main function
func main() {

	var resp []OpenedPorts
	fileName := "openedPorts.txt"

	listIPS := getAWSIPS()

	for _, element := range listIPS {
		p := portScanner(element)
		resp = append(resp, p)
	}

	if writeFile(resp, fileName) {
		sendMail(fileName)
	}

	fmt.Println("Done.")

}

// getAWSIPS search all ipv4 in the requested region
// Auth based in your home directory
func getAWSIPS() []string {

	var listPublicAddress []string

	sess, _ := session.NewSession(&aws.Config{
		Region: aws.String(os.Getenv("AWS_REGION"))},
	)

	svc := ec2.New(sess)
	result, _ := svc.DescribeAddresses(&ec2.DescribeAddressesInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("domain"),
				Values: aws.StringSlice([]string{"vpc"}),
			},
		},
	})

	if len(result.Addresses) == 0 {
		fmt.Printf("No elastic IPs for %s region\n", *svc.Config.Region)
	} else {
		for _, addr := range result.Addresses {
			listPublicAddress = append(listPublicAddress, aws.StringValue(addr.PublicIp))
		}
		return listPublicAddress
	}
	return listPublicAddress
}

// portScanner scan range 20-30000 through goroutines, opening a thread for each request
func portScanner(IPAddress string) OpenedPorts {

	var allowedPorts []int
	var portHasOpened OpenedPorts

	// 22 -> SSH, 443 -> SSL, 80 -> HTTP, 1194 -> OPENVPN
	allowedPorts = append(allowedPorts, 22, 443, 80, 1194)

	// 29980 threads := 1 thread = connection
	ps := portscanner.NewPortScanner(IPAddress, 2*time.Second, 29980)
	openedPorts := ps.GetOpenedPort(20, 30000)

	for i := 0; i < len(openedPorts); i++ {
		port := openedPorts[i]
		if !(contains(allowedPorts, port)) {
			portHasOpened.IP = IPAddress
			portHasOpened.PORT = append(portHasOpened.PORT, port)
		}
	}
	return portHasOpened
}

// writeFile creates and lists the portScanner output
func writeFile(resp []OpenedPorts, fileName string) bool {

	writed := false

	file, err := os.Create(fileName)

	if err != nil {
		log.Fatal("Cannot create file", err)
	}

	defer file.Close()

	for _, element := range resp {

		if element.PORT != nil && element.IP != "" {

			_, err := file.WriteString(fmt.Sprintf("-- IP: %s\n", element.IP))

			if err != nil {
				fmt.Printf("error writing string: %v", err)
			}

			for _, PORT := range element.PORT {
				_, err := file.WriteString(fmt.Sprintf("     • Porta: %d\n", PORT))
				if err != nil {
					fmt.Printf("error writing string: %v", err)
				}
			}

			writed = true
		}
	}
	return writed
}

// sendMail sends the email to the recipients including the log file
func sendMail(fileName string) {

	msg := "Segue em anexo as portas abertas com seus respectivos IPS:"

	// compose the message
	m := email.NewMessage(os.Getenv("SUBJECT"), msg)
	m.From = mail.Address{Name: "From", Address: os.Getenv("EMAIL_FROM")}
	m.To = []string{os.Getenv("EMAIL_TO")}

	// add attachments
	if err := m.Attach(fileName); err != nil {
		log.Fatal(err)
	}

	// send it
	auth := smtp.PlainAuth("", os.Getenv("EMAIL_AUTH"), os.Getenv("EMAIL_PASSWORD"), "smtp.gmail.com")
	if err := email.Send("smtp.gmail.com:587", auth, m); err != nil {
		log.Fatal(err)
	}
}

// contains compares the array with the object
func contains(slice []int, item int) bool {
	set := make(map[int]struct{}, len(slice))
	for _, s := range slice {
		set[s] = struct{}{}
	}

	_, ok := set[item]
	return ok
}