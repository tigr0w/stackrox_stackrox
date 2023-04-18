package mock

import (
	"bytes"
	"net/http"
)

const httpStatusUnset = -1

var _ http.ResponseWriter = (*ResponseWriter)(nil)

// ResponseWriter is stub implementation of http.ResponseWriter.
// It is basic implementation. It is NOT thread safe.
type ResponseWriter struct {
	Data    *bytes.Buffer
	Code    int
	headers http.Header
	err     error
}

func NewResponseWriter() *ResponseWriter {
	return NewFailingResponseWriter(nil)
}

// NewFailingResponseWriter returns implementation of http.ResponseWriter that returns error on attempt to write to it
// to emulate e.g. closed connection.
func NewFailingResponseWriter(err error) *ResponseWriter {
	return &ResponseWriter{
		Data:    bytes.NewBufferString(""),
		Code:    httpStatusUnset,
		headers: make(http.Header),
		err:     err,
	}
}

func (rw *ResponseWriter) Header() http.Header {
	return rw.headers
}

func (rw *ResponseWriter) Write(data []byte) (int, error) {
	if rw.err != nil {
		return 0, rw.err
	}
	if rw.Code == httpStatusUnset {
		rw.Code = http.StatusOK
	}
	return rw.Data.Write(data)
}

func (rw *ResponseWriter) WriteHeader(statusCode int) {
	rw.Code = statusCode
}
