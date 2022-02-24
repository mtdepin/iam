package internal

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/minio/madmin-go"
	config "mt-iam/conf"
	"os"
	"os/signal"
	"path"
	"sync"
	"syscall"
	"time"
)

var fileWritersMap sync.Map
var today int

const TIMEFORMAT = "2006-01-02-15-04-05"

type fileWriterS struct {
	//bucketLoggingConfig
	Writer *bufio.Writer
	files  []*os.File
	sync.RWMutex
}

func closeWriter(bucket string) {
	v, ok := fileWritersMap.Load(bucket)
	if !ok {
		return
	}
	fmt.Println("close fileWriter,reflush logging,bucket:", bucket)
	value := v.(*fileWriterS)
	if value.Writer.Buffered() > 0 {
		value.Writer.Flush()
	}
	if value.files[0] != nil {
		value.files[0].Close()
	}
	if value.files[1] != nil {
		value.files[1].Close()
	}
	fileWritersMap.Delete(bucket)
	fmt.Println("close fileWriter:", bucket, " success")
}

type BucketLoggingConfig struct {
	TargetBucket string
	TargetPrefix string
}

func consumeBucketLogging(ch chan interface{}) {
	exitChan := make(chan os.Signal)
	signal.Notify(exitChan, os.Interrupt, os.Kill, syscall.SIGTERM)
	go func() {
		<-exitChan
		fmt.Println("start close all fileWriter")
		bucketList := make([]string, 0)
		fileWritersMap.Range(func(key, value interface{}) bool {
			bucketList = append(bucketList, key.(string))
			return true
		})
		for _, ele := range bucketList {
			closeWriter(ele)
		}
		fmt.Println("start close all fileWriter finished")
	}()

	for c := range ch {
		if globalTrace.NumSubscribers() == 0 {
			// no subscriber
			return
		}
		traceInfo, ok := c.(madmin.TraceInfo)
		if !ok {
			return
		}
		bucket := traceInfo.StorageStats.Path
		v, exist := GloablLoggingConfig.Load(bucket)
		if !exist {
			return
		}
		conf, _ := v.(BucketLoggingConfig)
		writeBucketLogging(bucket, conf, map[string]interface{}{
			"ClientIP":     traceInfo.ReqInfo.Client,
			"NodeName":     traceInfo.NodeName,
			"Time":         traceInfo.Time,
			"Method":       traceInfo.ReqInfo.Method,
			"Bucket":       bucket,
			"Path":         traceInfo.ReqInfo.Path,
			"RawQuery":     traceInfo.ReqInfo.RawQuery,
			"Proto":        traceInfo.ReqInfo.Proto,
			"StatusCode":   traceInfo.RespInfo.StatusCode,
			"SendBytes":    traceInfo.CallStats.InputBytes,
			"RecivedBytes": traceInfo.CallStats.OutputBytes,
			"RequestTime":  traceInfo.CallStats.Latency.String(),
		})
	}
}

//<TargetPrefix><SourceBucket>YYYY-mm-DD-HH-MM-SS-UniqueString
func loggerInit(bucket string, bf BucketLoggingConfig) (*fileWriterS, error) {
	var fileWriter = &fileWriterS{
		//bucketLoggingConfig: bf,
		files: make([]*os.File, 2),
	}
	dir, _ := os.Getwd()
	multipartDir := config.GetString("nameserver-multidir")
	filePath := path.Join(dir, multipartDir, "bucketlogging")
	_, err := os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			_ = os.MkdirAll(filePath, os.ModePerm)
		} else {
			fmt.Println("log path err:", err)
			return nil, err
		}
	}
	fileBuffer := make([]*bufio.Writer, 2)
	fileBuffer[0] = nil
	fileBuffer[1] = nil
	today = time.Now().Hour()
	fileWriter.files[0], err = os.OpenFile(path.Join(filePath, fmt.Sprintf("%s%s%s-%s", bf.TargetPrefix, bucket, time.Now().Format(TIMEFORMAT), getBase64(bf.TargetBucket))), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		fmt.Println("open log file err: ", err)
		return nil, err
	}
	fileBuffer[0] = bufio.NewWriterSize(fileWriter.files[0], 4096)
	fileWriter.Writer = fileBuffer[0]
	go func() {
		time.Sleep(1 * time.Second)
		for {
			if fileWriter.Writer.Buffered() > 0 {
				fileWriter.RLock()
				err = fileWriter.Writer.Flush()
				if err != nil {
					fmt.Println("flush log file err", err)
					return
				}
				fileWriter.RUnlock()
			}
			//TODO 设计不合理
			time.Sleep(1 * time.Second)
			if today != time.Now().Hour() {
				today = time.Now().Hour()
				if fileWriter.files[0] == nil {
					fileWriter.files[0], err = os.OpenFile(path.Join(filePath, fmt.Sprintf("%s%s%s-%s", bf.TargetPrefix, bucket, time.Now().Format(TIMEFORMAT), getBase64(bf.TargetBucket))), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
					if err != nil {
						fmt.Println("open log file err: ", err)
						return
					}
					fileBuffer[0] = bufio.NewWriterSize(fileWriter.files[0], 4096)
					fileWriter.Writer = fileBuffer[0]
					if fileBuffer[1].Buffered() > 0 {
						fileBuffer[1].Flush()
					}
					fileBuffer[1] = nil
					GlobalNotifyCronJob <- fileWriter.files[1].Name()
					fileWriter.files[1].Close()
					fileWriter.files[1] = nil
				} else if fileWriter.files[1] == nil {
					fileWriter.files[1], err = os.OpenFile(path.Join(filePath, fmt.Sprintf("%s%s%s-%s", bf.TargetPrefix, bucket, time.Now().Format(TIMEFORMAT), getBase64(bf.TargetBucket))), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
					if err != nil {
						fmt.Println("open log file err: ", err)
						return
					}
					fileBuffer[1] = bufio.NewWriterSize(fileWriter.files[1], 4096)
					fileWriter.Writer = fileBuffer[1]
					if fileBuffer[0].Buffered() > 0 {
						fileBuffer[0].Flush()
					}
					fileBuffer[0] = nil
					GlobalNotifyCronJob <- fileWriter.files[0].Name()
					fileWriter.files[0].Close()
					fileWriter.files[0] = nil
				}
			}
		}
	}()
	return fileWriter, nil
}

func getBase64(targetBucket string) string {
	return base64.StdEncoding.EncodeToString([]byte(targetBucket))
}
func writeBucketLogging(bucket string, loggingConf BucketLoggingConfig, msg map[string]interface{}) {
	fileWriter, ok := fileWritersMap.Load(bucket)
	if !ok {
		//init writer
		fr, err := loggerInit(bucket, loggingConf)
		if err != nil {
			fmt.Println("loggerInit failed,bucket:", bucket)
			return
		}
		//store to fileWriters
		fileWritersMap.Store(bucket, fr)
	}
	fileWriter, _ = fileWritersMap.Load(bucket)
	writer := fileWriter.(*fileWriterS)

	bf := bytes.NewBuffer([]byte{})
	jsonEncoder := json.NewEncoder(bf)
	jsonEncoder.SetEscapeHTML(false)
	jsonEncoder.Encode(msg)
	a := bf.String()
	writer.Lock()
	writer.Writer.WriteString(a)
	writer.Unlock()
}
