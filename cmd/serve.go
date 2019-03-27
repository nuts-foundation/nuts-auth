package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/irmaserver"
	"github.com/sirupsen/logrus"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

const DefaultHttpPort = 3000

var httpPort int

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the service proxy",
	Long:  `Start the service proxy.`,
	Run: func(cmd *cobra.Command, args []string) {
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

		InitIRMA()

		logrus.Infof("starting with httpPort: %d", httpPort)

		// configure the router
		r := chi.NewRouter()
		r.Use(middleware.RequestID)
		r.Use(NewStructuredLogger(logrus.StandardLogger()))
		r.Get("/", func(writer http.ResponseWriter, request *http.Request) {
			writer.Write([]byte("Welcome Nuts proxy!"))
		})
		r.Post("/auth/contract/session", CreateSessionHandler)

		addr := fmt.Sprintf(":%d", httpPort)
		httpServer := &http.Server{Addr: addr, Handler: r}

		ctx, cancel := context.WithCancel(context.Background())

		go func() {
			if err := httpServer.ListenAndServe(); err != nil {
				logrus.Panicf("Could not start server: %s", err)
			}
		}()

		<-stop
		logrus.Info("Shutting down the server")
		httpServer.Shutdown(ctx)

		cancel()
	},
}

func NewStructuredLogger(logger *logrus.Logger) func(next http.Handler) http.Handler {
	return middleware.RequestLogger(&StructuredLogger{logger})
}

type StructuredLogger struct {
	Logger *logrus.Logger
}

func (l *StructuredLogger) NewLogEntry(r *http.Request) middleware.LogEntry {
	entry := &StructuredLoggerEntry{Logger: logrus.NewEntry(l.Logger)}
	logFields := logrus.Fields{}

	logFields["ts"] = time.Now().UTC().Format(time.RFC1123)

	if reqID := middleware.GetReqID(r.Context()); reqID != "" {
		logFields["req_id"] = reqID
	}

	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	logFields["http_scheme"] = scheme
	logFields["http_proto"] = r.Proto
	logFields["http_method"] = r.Method

	logFields["remote_addr"] = r.RemoteAddr
	logFields["user_agent"] = r.UserAgent()
	logFields["request_id"] = middleware.GetReqID(r.Context())

	logFields["uri"] = fmt.Sprintf("%s://%s%s", scheme, r.Host, r.RequestURI)

	entry.Logger = entry.Logger.WithFields(logFields)

	entry.Logger.Infoln("request started")

	return entry
}

type StructuredLoggerEntry struct {
	Logger logrus.FieldLogger
}

func (l *StructuredLoggerEntry) Write(status, bytes int, elapsed time.Duration) {
	l.Logger = l.Logger.WithFields(logrus.Fields{
		"resp_status": status, "resp_bytes_length": bytes,
		"resp_elapsed_ms": float64(elapsed.Nanoseconds()) / 1000000.0,
	})

	l.Logger.Infoln("request complete")
}

func (l *StructuredLoggerEntry) Panic(v interface{}, stack []byte) {
	l.Logger = l.Logger.WithFields(logrus.Fields{
		"stack": string(stack),
		"panic": fmt.Sprintf("%+v", v),
	})
}

func InitIRMA() {
	configuration := &server.Configuration{
		URL:    "http://localhost:1234/irma",
		Logger: logrus.StandardLogger(),
	}

	logrus.Info("Initializing IRMA library...")
	if err := irmaserver.Initialize(configuration); err != nil {
		logrus.Panic("Could not initialize IRMA library:", err)
	}
}

func CreateSessionHandler(writer http.ResponseWriter, _ *http.Request) {
	requestDefenition := `{
			"type": "disclosing",
			"content": [{ "label": "Full name", "attributes": [ "pbdf.nijmegen.personalData.fullname" ]}]
		}`

	sessionPointer, token, err := irmaserver.StartSession(requestDefenition, func(result *server.SessionResult) {
		logrus.Infof("session done, result: %s", server.ToJson(result))
	})

	if err != nil {
		logrus.Panicf("error while creating session: ", err)
	}

	logrus.Infof("session created with token: %s", token)

	jsonSessionPointer, _ := json.Marshal(sessionPointer)
	writer.WriteHeader(http.StatusCreated)
	_, err = writer.Write(jsonSessionPointer)
	if err != nil {
		logrus.Panicf("Write failed: %v", err)
	}
}

func init() {
	rootCmd.AddCommand(serveCmd)
	serveCmd.Flags().IntVarP(&httpPort, "httpPort", "p", DefaultHttpPort, "The port the http server should bind to")
}
