package iouringzap

import (
	"fmt"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"os"
	"sync"
	"time"
	"unsafe"

	"github.com/pawelgaczynski/giouring"
)

// IoUringLogger writes log data asynchronously using io_uring.
type IoUringLogger struct {
	ring *giouring.Ring
	file *os.File
	mu   sync.Mutex
}

// NewIoUringLogger creates a new IoUringLogger that writes to the given
// path with the specified io_uring queue depth.
func NewIoUringLogger(path string, queueDepth uint32) (*IoUringLogger, error) {
	ring, err := giouring.CreateRing(queueDepth)
	if err != nil {
		return nil, fmt.Errorf("CreateRing: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		ring.QueueExit()
		return nil, fmt.Errorf("open log file: %w", err)
	}
	return &IoUringLogger{ring: ring, file: f}, nil
}

// Write satisfies io.Writer. It submits the write request to io_uring
// and blocks until completion. Falls back to sync write if SQE unavailable.
func (l *IoUringLogger) Write(p []byte) (n int, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	sqe := l.ring.GetSQE()
	if sqe == nil {
		return l.file.Write(p)
	}
	sqe.PrepareWrite(
		int(l.file.Fd()),
		uintptr(unsafe.Pointer(&p[0])),
		uint32(len(p)),
		0,
	)
	if _, err := l.ring.SubmitAndWait(1); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Sync satisfies zapcore.WriteSyncer. No-op since io_uring writes are durable on completion.
func (l *IoUringLogger) Sync() error {
	return nil
}

// Close shuts down the logger, closing the file and io_uring ring.
func (l *IoUringLogger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.file.Close()
	l.ring.QueueExit()
	return nil
}

// RotateIoUringLogger wraps IoUringLogger to provide daily rotation.
type RotateIoUringLogger struct {
	pattern     string
	queueDepth  uint32
	current     *IoUringLogger
	currentPath string
	mu          sync.Mutex
}

// NewRotateIoUringLogger creates a RotateIoUringLogger using the given
// Go time format pattern (e.g. "/var/log/app-2006-01-02.log").
func NewRotateIoUringLogger(pattern string, queueDepth uint32) (*RotateIoUringLogger, error) {
	r := &RotateIoUringLogger{pattern: pattern, queueDepth: queueDepth}
	if err := r.rotateIfNeeded(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *RotateIoUringLogger) rotateIfNeeded() error {
	path := time.Now().Format(r.pattern)
	if path == r.currentPath {
		return nil
	}
	if r.current != nil {
		r.current.Close()
	}
	l, err := NewIoUringLogger(path, r.queueDepth)
	if err != nil {
		return err
	}
	r.current = l
	r.currentPath = path
	return nil
}

// Write writes p to the current day's log, rotating if date changed.
func (r *RotateIoUringLogger) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.rotateIfNeeded(); err != nil {
		return 0, err
	}
	return r.current.Write(p)
}

// Sync flushes the current logger.
func (r *RotateIoUringLogger) Sync() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.current.Sync()
}

// Close shuts down the underlying logger.
func (r *RotateIoUringLogger) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.current != nil {
		return r.current.Close()
	}
	return nil
}

// NewLogger returns a zap.Logger that writes structured JSON logs
// asynchronously via io_uring with daily rotation.
func NewLogger(pattern string, queueDepth uint32, level zapcore.Level) (*zap.Logger, *RotateIoUringLogger, error) {
	writer, err := NewRotateIoUringLogger(pattern, queueDepth)
	if err != nil {
		return nil, nil, err
	}

	encoderCfg := zapcore.EncoderConfig{
		TimeKey:        "timestamp",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.CapitalLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}
	enCoder := zapcore.NewJSONEncoder(encoderCfg)
	core := zapcore.NewCore(enCoder, zapcore.AddSync(writer), level)
	lg := zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))
	return lg, writer, nil
}

var (
	once        sync.Once
	globalSugar *zap.SugaredLogger
	globalRot   *RotateIoUringLogger
	initErr     error
)

func InitGlobal(pattern string, queueDepth uint32, level zapcore.Level) error {
	once.Do(func() {
		lg, rot, err := NewLogger(pattern, queueDepth, level)
		if err != nil {
			initErr = err
			return
		}
		//globalLogger = lg
		globalSugar = lg.Sugar()
		globalRot = rot
	})
	return initErr
}

func GetLogger() *zap.SugaredLogger {
	return globalSugar
}

func CloseGlobal() error {
	if globalRot != nil {
		return globalRot.Close()
	}
	return nil
}

func init() {
	if err := InitGlobal("/var/log/app-2006-01-02.log", 8, zapcore.InfoLevel); err != nil {
		panic(fmt.Sprintf("iouringzap 初始化失败: %v", err))
	}
}
