package logger


import (
	"github.com/lestrrat-go/strftime"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
	"os"
	"strings"
	"time"
)

var logger *zap.SugaredLogger

func genFilename(pattern *strftime.Strftime) string {
	now := time.Now()

	// XXX HACK: Truncate only happens in UTC semantics, apparently.
	// observed values for truncating given time with 86400 secs:
	//
	// before truncation: 2018/06/01 03:54:54 2018-06-01T03:18:00+09:00
	// after  truncation: 2018/06/01 03:54:54 2018-05-31T09:00:00+09:00
	//
	// This is really annoying when we want to truncate in local time
	// so we hack: we take the apparent local time in the local zone,
	// and pretend that it's in UTC. do our math, and put it back to
	// the local zone
	var base time.Time
	if now.Location() != time.UTC {
		base = time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute(), now.Second(), now.Nanosecond(), time.UTC)
		base = time.Date(base.Year(), base.Month(), base.Day(), base.Hour(), base.Minute(), base.Second(), base.Nanosecond(), base.Location())
	} else {
		base = time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute(), now.Second(), now.Nanosecond(), time.UTC)
	}
	return pattern.FormatString(base)
}

func InitLogger(level string) {
	curPath, _ := os.Getwd()
	f, _ := strftime.New(strings.Replace(curPath+"/logs/out.log", ".log", "", -1) + "-%Y-%m-%d-%H%M.log")
	fn := genFilename(f)
	hook := lumberjack.Logger{
		Filename:   fn,   // 日志文件路径
		MaxSize:    128,  // 每个日志文件保存的最大尺寸 单位：M
		MaxBackups: 30,   // 日志文件最多保存多少个备份
		MaxAge:     7,    // 文件最多保存多少天
		Compress:   true, // 是否压缩
	}

	// 设置一些基本日志格式 具体含义还比较好理解，直接看zap源码也不难懂
	encoder := zapcore.NewConsoleEncoder(zapcore.EncoderConfig{
		MessageKey:  "msg",
		LevelKey:    "level",
		EncodeLevel: zapcore.CapitalLevelEncoder,
		TimeKey:     "ts",
		EncodeTime: func(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
			enc.AppendString(t.Format("2006-01-02 15:04:05"))
		},
		CallerKey:    "file",
		EncodeCaller: zapcore.ShortCallerEncoder,
		EncodeDuration: func(d time.Duration, enc zapcore.PrimitiveArrayEncoder) {
			enc.AppendInt64(int64(d) / 1000000)
		},
	})

	l := getLevel(level)
	// 设置日志级别
	atomicLevel := zap.NewAtomicLevel()
	//atomicLevel.SetLevel(zap.InfoLevel)
	atomicLevel.SetLevel(l)

	core := zapcore.NewCore(
		encoder,
		// 编码器配置
		//zapcore.NewJSONEncoder(encoderConfig),                                           // 编码器配置
		zapcore.NewMultiWriteSyncer(zapcore.AddSync(os.Stdout), zapcore.AddSync(&hook)), // 打印到控制台和文件
		atomicLevel, // 日志级别
	)
	// 开启开发模式，堆栈跟踪
	caller := zap.AddCaller()
	// 开启文件及行号
	development := zap.Development()
	log := zap.New(core, zap.AddCaller(), caller, development, zap.AddCallerSkip(1)) // 需要传入 zap.AddCaller() 才会显示打日志点的文件名和行数,
	log = log.WithOptions(zap.AddCaller())
	logger = log.Sugar()

}

func getLevel(level string) zapcore.Level {
	level = strings.ToLower(level)
	switch level {
	case "info":
		return zap.InfoLevel
	case "debug":
		return zap.DebugLevel
	case "storageerror":
		return zap.ErrorLevel
	case "fatal":
		return zap.FatalLevel
	case "panic":
		return zap.DPanicLevel
	default:
		return zap.InfoLevel
	}
}

func Debug(args ...interface{}) {
	logger.Debug(args...)
}

func Debugf(template string, args ...interface{}) {
	logger.Debugf(template, args...)
}

func Info(args ...interface{}) {
	logger.Info(args...)
}

func Infof(template string, args ...interface{}) {
	logger.Infof(template, args...)
}

func Warn(args ...interface{}) {
	logger.Warn(args...)
}

func Warnf(template string, args ...interface{}) {
	logger.Warnf(template, args...)
}

func Error(args ...interface{}) {
	logger.Error(args...)
}

func Errorf(template string, args ...interface{}) {
	logger.Errorf(template, args...)
}

func DPanic(args ...interface{}) {
	logger.DPanic(args...)
}

func DPanicf(template string, args ...interface{}) {
	logger.DPanicf(template, args...)
}

func Panic(args ...interface{}) {
	logger.Panic(args...)
}

func Panicf(template string, args ...interface{}) {
	logger.Panicf(template, args...)
}

func Fatal(args ...interface{}) {
	logger.Fatal(args...)
}

func Fatalf(template string, args ...interface{}) {
	logger.Fatalf(template, args...)
}
