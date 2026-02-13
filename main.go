package main

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rwcarlsen/goexif/exif"
)

// 检查并杀掉占用端口的进程
func killPortProcess(port int) {
	if runtime.GOOS == "windows" {
		// Windows: 使用 netstat 找到 PID，然后 taskkill
		out, err := exec.Command("cmd", "/c", fmt.Sprintf("netstat -ano | findstr :%d", port)).Output()
		if err != nil {
			return // 端口未被占用
		}
		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) >= 5 && strings.Contains(fields[1], fmt.Sprintf(":%d", port)) {
				pid := fields[len(fields)-1]
				exec.Command("taskkill", "/F", "/PID", pid).Run()
				fmt.Printf("已清理端口 %d 上的旧进程 (PID: %s)\n", port, pid)
			}
		}
	} else {
		// Linux/Mac: 使用 lsof 或 fuser
		exec.Command("sh", "-c", fmt.Sprintf("lsof -ti:%d | xargs kill -9", port)).Run()
	}
}

// 打开默认浏览器
func openBrowser(url string) {
	var err error
	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("cmd", "/c", "start", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	}
	if err != nil {
		fmt.Printf("无法打开浏览器: %v\n", err)
	}
}

type PhotoInfo struct {
	Name string `json:"name"`
	URL  string `json:"url"`
	Type string `json:"type"` // "image" or "video"
}

type PhotoGroup struct {
	Date   string      `json:"date"`
	Count  int         `json:"count"`
	Photos []PhotoInfo `json:"photos,omitempty"`
}

type BabyConfig struct {
	BirthDate string `json:"birthDate"`
}

// 获取文件拍摄日期
func getShootingDate(file io.Reader) time.Time {
	x, err := exif.Decode(file)
	if err == nil {
		tm, err := x.DateTime()
		if err == nil {
			return tm
		}
	}
	return time.Time{}
}

// 从文件名中解析日期
func parseDateFromFilename(filename string) time.Time {
	// 1. 匹配 13位毫秒时间戳
	reMs := regexp.MustCompile(`\d{13}`)
	if match := reMs.FindString(filename); match != "" {
		ts, err := strconv.ParseInt(match, 10, 64)
		if err == nil {
			return time.Unix(0, ts*int64(time.Millisecond))
		}
	}

	// 2. 匹配 10位秒级时间戳
	reS := regexp.MustCompile(`\d{10}`)
	if match := reS.FindString(filename); match != "" {
		ts, err := strconv.ParseInt(match, 10, 64)
		if err == nil {
			return time.Unix(ts, 0)
		}
	}

	// 3. 匹配 YYYY-MM-DD 或 YYYY_MM_DD 或 YYYYMMDD
	reDate := regexp.MustCompile(`(\d{4})[-_]?(\d{2})[-_]?(\d{2})`)
	if match := reDate.FindStringSubmatch(filename); len(match) > 0 {
		t, err := time.Parse("2006-01-02", fmt.Sprintf("%s-%s-%s", match[1], match[2], match[3]))
		if err == nil {
			return t
		}
	}

	return time.Time{}
}

// 获取视频创建日期 (需要 ffprobe.exe 在项目根目录)
func getVideoCreationDate(videoPath string) time.Time {
	ffprobePath := "./ffprobe.exe"
	if runtime.GOOS == "windows" {
		if _, err := os.Stat(ffprobePath); os.IsNotExist(err) {
			ffprobePath = "ffprobe"
		}
	} else {
		ffprobePath = "ffprobe"
	}

	// 1. 尝试从流元数据获取
	cmd := exec.Command(ffprobePath,
		"-v", "quiet",
		"-select_streams", "v:0",
		"-show_entries", "stream_tags=creation_time",
		"-of", "default=noprint_wrappers=1:nokey=1",
		videoPath)

	out, _ := cmd.Output()
	dateStr := strings.TrimSpace(string(out))

	// 2. 如果流里没有，尝试从格式元数据获取
	if dateStr == "" {
		cmd = exec.Command(ffprobePath,
			"-v", "quiet",
			"-show_entries", "format_tags=creation_time",
			"-of", "default=noprint_wrappers=1:nokey=1",
			videoPath)
		out, _ = cmd.Output()
		dateStr = strings.TrimSpace(string(out))
	}

	if dateStr != "" {
		t, err := time.Parse(time.RFC3339, dateStr)
		if err == nil {
			return t.Local()
		}
		// 某些格式可能略有不同，尝试简单格式解析
		t, err = time.Parse("2006-01-02 15:04:05", dateStr)
		if err == nil {
			return t.Local()
		}
	}

	return time.Time{}
}

// 文件名格式为 日期_hash.ext（如 20060102_a1b2c3d4...jpg），检查是否存在相同 hash 的文件
func findDuplicateFile(baseDir, fileHash, ext string) (string, bool) {
	var foundPath string
	filepath.Walk(baseDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if strings.Contains(path, "_duplicates") {
				return filepath.SkipDir
			}
			return nil
		}
		baseName := strings.TrimSuffix(info.Name(), ext)
		if baseName != info.Name() && strings.HasSuffix(baseName, "_"+fileHash) {
			foundPath = path
			return filepath.SkipAll
		}
		return nil
	})
	return foundPath, foundPath != ""
}

// 读取出生日期配置
func loadBabyConfig(configPath string) (*BabyConfig, error) {
	config := &BabyConfig{}

	// 如果文件不存在，返回空配置
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return config, nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	if len(data) == 0 {
		return config, nil
	}

	err = json.Unmarshal(data, config)
	if err != nil {
		return nil, err
	}

	return config, nil
}

// 保存出生日期配置
func saveBabyConfig(configPath string, config *BabyConfig) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(configPath, data, 0644)
}

var (
	dupMu    sync.RWMutex
	dupIndex = make(map[string]struct{})

	videoQ       chan videoTask
	videoEnqMu   sync.Mutex
	videoEnqSeen = make(map[string]struct{})
	videoDropped atomic.Int64
)

type videoTask struct {
	path       string
	fileHash   string
	ext        string
	targetDate time.Time
}

func buildDupIndex(baseDir string) {
	_ = filepath.Walk(baseDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if strings.Contains(path, "_duplicates") {
				return filepath.SkipDir
			}
			return nil
		}

		ext := strings.ToLower(filepath.Ext(info.Name()))
		name := strings.TrimSuffix(info.Name(), ext)
		// 期望格式：YYYYMMDD_hash
		idx := strings.LastIndex(name, "_")
		if idx <= 0 || idx == len(name)-1 {
			return nil
		}
		h := name[idx+1:]
		if len(h) != 32 {
			return nil
		}

		dupMu.Lock()
		dupIndex[h+ext] = struct{}{}
		dupMu.Unlock()
		return nil
	})
}

func enqueueVideoTask(t videoTask) {
	if videoQ == nil {
		return
	}
	videoEnqMu.Lock()
	if _, ok := videoEnqSeen[t.path]; ok {
		videoEnqMu.Unlock()
		return
	}
	videoEnqSeen[t.path] = struct{}{}
	videoEnqMu.Unlock()

	select {
	case videoQ <- t:
	default:
		videoDropped.Add(1)
		videoEnqMu.Lock()
		delete(videoEnqSeen, t.path)
		videoEnqMu.Unlock()
	}
}

func startVideoWorker(baseDir string) {
	if videoQ == nil {
		return
	}
	go func() {
		for t := range videoQ {
			vDate := getVideoCreationDate(t.path)
			if !vDate.IsZero() && vDate.Format("20060102") != t.targetDate.Format("20060102") {
				newTargetDate := vDate
				newDatePath := filepath.Join(newTargetDate.Format("2006"), newTargetDate.Format("01"), newTargetDate.Format("02"))
				newUploadDir := filepath.Join(baseDir, newDatePath)
				_ = os.MkdirAll(newUploadDir, 0755)
				newFileNameV := newTargetDate.Format("20060102") + "_" + t.fileHash + t.ext
				newDstPath := filepath.Join(newUploadDir, newFileNameV)
				if _, err := os.Stat(newDstPath); err != nil {
					_ = os.Rename(t.path, newDstPath)
				}
			}

			videoEnqMu.Lock()
			delete(videoEnqSeen, t.path)
			videoEnqMu.Unlock()
		}
	}()
}

// 处理归档逻辑的通用函数
func processCompletedFile(filePath string, filename string, lastModified string, baseDir string, tempDir string) gin.H {
	src, err := os.Open(filePath)
	if err != nil {
		return gin.H{"filename": filename, "status": "fail", "error": "无法打开合并后的文件"}
	}
	defer src.Close()

	ext := strings.ToLower(filepath.Ext(filename))
	// 1. 尝试读取拍摄日期 (EXIF/文件名/客户端时间)
	shootingDate := getShootingDate(src)
	if shootingDate.IsZero() {
		shootingDate = parseDateFromFilename(filename)
	}

	_, _ = src.Seek(0, 0)

	// 2. 计算 MD5 去重
	hash := md5.New()
	if _, err := io.Copy(hash, src); err != nil {
		return gin.H{"filename": filename, "status": "fail", "error": "哈希计算失败"}
	}
	fileHash := fmt.Sprintf("%x", hash.Sum(nil))
	_ = src.Close() // 重新打开前先关闭

	// 3. 确定最终日期
	var targetDate time.Time
	isDateConfirmed := true

	if !shootingDate.IsZero() {
		targetDate = shootingDate
	} else if lastModified != "" {
		ms, err := strconv.ParseInt(lastModified, 10, 64)
		if err == nil {
			targetDate = time.Unix(0, ms*int64(time.Millisecond))
			isDateConfirmed = false
		}
	}

	if targetDate.IsZero() || !isDateConfirmed {
		fnDate := parseDateFromFilename(filename)
		if !fnDate.IsZero() {
			targetDate = fnDate
			isDateConfirmed = true
		}
	}

	if targetDate.IsZero() {
		targetDate = time.Now()
		isDateConfirmed = false
	}

	// 4. 路径处理
	datePath := targetDate.Format("2006/01/02")
	newFileName := targetDate.Format("20060102") + "_" + fileHash + ext
	var finalDstPath string
	var relURL string

	if !isDateConfirmed {
		finalDstPath = filepath.Join(tempDir, fileHash+ext)
		relURL = "/public/babyphoto/_temp/" + fileHash + ext
	} else {
		uploadDir := filepath.Join(baseDir, filepath.FromSlash(datePath))
		_ = os.MkdirAll(uploadDir, 0755)
		finalDstPath = filepath.Join(uploadDir, newFileName)
		relURL = "/public/babyphoto/" + datePath + "/" + newFileName
	}

	// 全局索引判重
	dupMu.RLock()
	_, isDuplicate := dupIndex[fileHash+ext]
	dupMu.RUnlock()

	if isDuplicate {
		duplicateDir := filepath.Join(baseDir, "_duplicates")
		_ = os.MkdirAll(duplicateDir, 0755)
		timestamp := time.Now().Format("20060102_150405")
		duplicateFileName := fmt.Sprintf("%s_%s_%s%s", targetDate.Format("20060102"), timestamp, fileHash, ext)
		duplicatePath := filepath.Join(duplicateDir, duplicateFileName)
		_ = os.Rename(filePath, duplicatePath)
		return gin.H{
			"filename": filename,
			"status":   "duplicate",
			"url":      "/public/babyphoto/_duplicates/" + duplicateFileName,
		}
	}

	// 移动文件到最终位置
	if _, err := os.Stat(finalDstPath); err == nil {
		_ = os.Remove(filePath)
	} else {
		_ = os.Rename(filePath, finalDstPath)
	}

	// 视频异步修正
	isVideo := ext == ".mp4" || ext == ".mov" || ext == ".avi"
	if isVideo {
		enqueueVideoTask(videoTask{
			path:       finalDstPath,
			fileHash:   fileHash,
			ext:        ext,
			targetDate: targetDate,
		})
	}

	status := "success"
	if !isDateConfirmed {
		status = "need_confirm"
	}

	if status == "success" {
		dupMu.Lock()
		dupIndex[fileHash+ext] = struct{}{}
		dupMu.Unlock()
	}

	return gin.H{
		"filename": filename,
		"status":   status,
		"url":      relURL,
		"hash":     fileHash,
		"ext":      ext,
		"date":     targetDate.Format("2006-01-02"),
	}
}

func main() {
	port := 8080
	// 1. 自动处理端口冲突
	killPortProcess(port)

	// 设置为发布模式减少日志，或者保持默认 debug 模式
	// gin.SetMode(gin.ReleaseMode)

	r := gin.Default()

	// 允许上传的最大内存
	r.MaxMultipartMemory = 2 << 30 // 2 GiB

	// 基础目录
	baseDir := "./public/babyphoto"
	tempDir := filepath.Join(baseDir, "_temp")
	// 确保基础目录和临时目录存在
	os.MkdirAll(tempDir, 0755)

	// 配置文件路径
	configPath := "./baby_config.json"

	// 初始化全局索引和异步队列
	videoQ = make(chan videoTask, 1000)
	buildDupIndex(baseDir)
	startVideoWorker(baseDir)

	// 兼容旧的整文件上传接口（前端切片后将走 /api/upload/*）
	// --- 切片上传接口 ---
	chunkBaseDir := filepath.Join(baseDir, "_chunks")
	os.MkdirAll(chunkBaseDir, 0755)

	// 1. 初始化上传
	r.POST("/api/upload/init", func(c *gin.Context) {
		var req struct {
			Filename     string `json:"filename" binding:"required"`
			Size         int64  `json:"size" binding:"required"`
			ChunkSize    int    `json:"chunkSize" binding:"required"`
			LastModified string `json:"lastModified"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "参数错误"})
			return
		}

		uploadId := fmt.Sprintf("%d_%x", time.Now().UnixNano(), md5.Sum([]byte(req.Filename)))
		uploadPath := filepath.Join(chunkBaseDir, uploadId)
		os.MkdirAll(uploadPath, 0755)

		c.JSON(http.StatusOK, gin.H{
			"uploadId": uploadId,
		})
	})

	// 2. 接收切片
	r.POST("/api/upload/chunk", func(c *gin.Context) {
		uploadId := c.PostForm("uploadId")
		index := c.PostForm("index")
		file, err := c.FormFile("chunk")
		if err != nil || uploadId == "" || index == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "无效的切片数据"})
			return
		}

		uploadPath := filepath.Join(chunkBaseDir, uploadId)
		if _, err := os.Stat(uploadPath); os.IsNotExist(err) {
			c.JSON(http.StatusNotFound, gin.H{"error": "上传任务不存在"})
			return
		}

		chunkPath := filepath.Join(uploadPath, index+".part")
		if err := c.SaveUploadedFile(file, chunkPath); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "保存切片失败"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "切片保存成功"})
	})

	// 3. 完成上传（合并并归档）
	r.POST("/api/upload/complete", func(c *gin.Context) {
		var req struct {
			UploadId     string `json:"uploadId" binding:"required"`
			Filename     string `json:"filename" binding:"required"`
			LastModified string `json:"lastModified"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "参数错误"})
			return
		}

		uploadPath := filepath.Join(chunkBaseDir, req.UploadId)
		files, err := os.ReadDir(uploadPath)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "无法读取切片目录"})
			return
		}

		// 合并文件
		ext := filepath.Ext(req.Filename)
		mergedFilePath := filepath.Join(tempDir, req.UploadId+ext)
		mergedFile, err := os.Create(mergedFilePath)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "无法创建合并文件"})
			return
		}

		// 排序分片
		sort.Slice(files, func(i, j int) bool {
			idxI, _ := strconv.Atoi(strings.TrimSuffix(files[i].Name(), ".part"))
			idxj, _ := strconv.Atoi(strings.TrimSuffix(files[j].Name(), ".part"))
			return idxI < idxj
		})

		for _, f := range files {
			fPath := filepath.Join(uploadPath, f.Name())
			chunkData, err := os.ReadFile(fPath)
			if err != nil {
				mergedFile.Close()
				c.JSON(http.StatusInternalServerError, gin.H{"error": "读取切片失败"})
				return
			}
			mergedFile.Write(chunkData)
		}
		mergedFile.Close()

		// 清理切片目录
		os.RemoveAll(uploadPath)

		// 调用通用处理逻辑
		result := processCompletedFile(mergedFilePath, req.Filename, req.LastModified, baseDir, tempDir)
		c.JSON(http.StatusOK, result)
	})

	r.POST("/upload", func(c *gin.Context) {
		form, err := c.MultipartForm()
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "无法解析表单: " + err.Error()})
			return
		}

		files := form.File["files"]
		if len(files) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "没有找到上传的文件"})
			return
		}

		// 可选：客户端传递的原始文件修改时间（毫秒时间戳，来自浏览器 File.lastModified）
		// 约定：lastModifieds 的顺序与 files 一致。
		lastModifieds := form.Value["lastModifieds"]

		type job struct {
			idx  int
			file *multipart.FileHeader
			last string
		}

		jobs := make(chan job)
		results := make([]gin.H, len(files))

		workerCount := runtime.NumCPU()
		if workerCount < 2 {
			workerCount = 2
		}
		if workerCount > 8 {
			workerCount = 8
		}

		var wg sync.WaitGroup
		wg.Add(workerCount)

		for w := 0; w < workerCount; w++ {
			go func() {
				defer wg.Done()
				for j := range jobs {
					file := j.file
					src, err := file.Open()
					if err != nil {
						results[j.idx] = gin.H{"filename": file.Filename, "status": "fail", "error": "无法打开文件"}
						continue
					}

					ext := strings.ToLower(filepath.Ext(file.Filename))
					isVideo := ext == ".mp4" || ext == ".mov" || ext == ".avi"

					// 1. 尝试读取拍摄日期 (EXIF/文件名/客户端时间)
					shootingDate := getShootingDate(src)
					if shootingDate.IsZero() {
						shootingDate = parseDateFromFilename(file.Filename)
					}

					if seeker, ok := src.(io.Seeker); ok {
						_, _ = seeker.Seek(0, 0)
					}

					// 2. 计算 MD5 去重
					hash := md5.New()
					if _, err := io.Copy(hash, src); err != nil {
						_ = src.Close()
						results[j.idx] = gin.H{"filename": file.Filename, "status": "fail", "error": "哈希计算失败"}
						continue
					}
					fileHash := fmt.Sprintf("%x", hash.Sum(nil))

					// 3. 确定最终日期：优先 EXIF/文件名，最后用客户端时间或标记为待确认
					var targetDate time.Time
					isDateConfirmed := true

					if !shootingDate.IsZero() {
						targetDate = shootingDate
					} else if j.last != "" {
						ms, err := strconv.ParseInt(j.last, 10, 64)
						if err == nil {
							targetDate = time.Unix(0, ms*int64(time.Millisecond))
							// 只有从文件名或 EXIF 解析出的才算“已确认”
							isDateConfirmed = false
						}
					}

					// 如果文件名里有日期，且之前还没拿到日期，再补一次
					if targetDate.IsZero() || !isDateConfirmed {
						fnDate := parseDateFromFilename(file.Filename)
						if !fnDate.IsZero() {
							targetDate = fnDate
							isDateConfirmed = true
						}
					}

					if targetDate.IsZero() {
						targetDate = time.Now()
						isDateConfirmed = false
					}

					// 4. 路径处理：只有不确定日期的文件进入 _temp，解析出日期的（包括视频）直接归类
					var dstPath string
					var relURL string
					datePath := targetDate.Format("2006/01/02")
					newFileName := targetDate.Format("20060102") + "_" + fileHash + ext

					if !isDateConfirmed {
						// 只有无法确定日期的文件放临时目录
						dstPath = filepath.Join(tempDir, fileHash+ext)
						relURL = "/public/babyphoto/_temp/" + fileHash + ext
					} else {
						uploadDir := filepath.Join(baseDir, filepath.FromSlash(datePath))
						_ = os.MkdirAll(uploadDir, 0755)
						dstPath = filepath.Join(uploadDir, newFileName)
						relURL = "/public/babyphoto/" + datePath + "/" + newFileName
					}

					isDuplicate := false
					duplicateDir := filepath.Join(baseDir, "_duplicates")

					// 全局索引判重 (O(1))
					dupMu.RLock()
					_, isDuplicate = dupIndex[fileHash+ext]
					dupMu.RUnlock()

					if isDuplicate {
						if err := os.MkdirAll(duplicateDir, 0755); err != nil {
							_ = src.Close()
							results[j.idx] = gin.H{"filename": file.Filename, "status": "fail", "error": "创建重复文件目录失败"}
							continue
						}

						timestamp := time.Now().Format("20060102_150405")
						duplicateFileName := fmt.Sprintf("%s_%s_%s%s", targetDate.Format("20060102"), timestamp, fileHash, ext)
						duplicatePath := filepath.Join(duplicateDir, duplicateFileName)
						duplicateURL := "/public/babyphoto/_duplicates/" + duplicateFileName

						if seeker, ok := src.(io.Seeker); ok {
							_, err = seeker.Seek(0, 0)
							if err != nil {
								_ = src.Close()
								results[j.idx] = gin.H{"filename": file.Filename, "status": "fail", "error": "文件重置失败"}
								continue
							}
						}

						out, err := os.Create(duplicatePath)
						if err != nil {
							_ = src.Close()
							results[j.idx] = gin.H{"filename": file.Filename, "status": "fail", "error": "创建重复文件失败"}
							continue
						}

						_, err = io.Copy(out, src)
						_ = out.Close()
						_ = src.Close()

						results[j.idx] = gin.H{
							"filename": file.Filename,
							"status":   "duplicate",
							"url":      duplicateURL,
						}
						continue
					}

					if seeker, ok := src.(io.Seeker); ok {
						_, _ = seeker.Seek(0, 0)
					}

					out, err := os.Create(dstPath)
					if err != nil {
						_ = src.Close()
						results[j.idx] = gin.H{"filename": file.Filename, "status": "fail", "error": "保存临时文件失败"}
						continue
					}

					_, err = io.Copy(out, src)
					_ = out.Close()
					_ = src.Close()

					// 异步处理视频日期修正
					if isVideo {
						enqueueVideoTask(videoTask{
							path:       dstPath,
							fileHash:   fileHash,
							ext:        ext,
							targetDate: targetDate,
						})
					}

					status := "success"
					if !isDateConfirmed {
						status = "need_confirm"
					}

					results[j.idx] = gin.H{
						"filename": file.Filename,
						"status":   status,
						"url":      relURL,
						"tempPath": dstPath,
						"hash":     fileHash,
						"ext":      ext,
						"date":     targetDate.Format("2006-01-02"),
					}

					if status == "success" {
						dupMu.Lock()
						dupIndex[fileHash+ext] = struct{}{}
						dupMu.Unlock()
					}
				}
			}()
		}

		for i, file := range files {
			last := ""
			if i < len(lastModifieds) {
				last = lastModifieds[i]
			}
			jobs <- job{idx: i, file: file, last: last}
		}
		close(jobs)
		wg.Wait()

		c.JSON(http.StatusOK, gin.H{
			"message": fmt.Sprintf("处理完成，共 %d 个文件", len(files)),
			"results": results,
		})
	})

	// 获取所有照片索引接口（仅返回日期和数量）
	r.GET("/api/photos", func(c *gin.Context) {
		groupsMap := make(map[string]int)

		err := filepath.Walk(baseDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				base := filepath.Base(path)
				// 这些目录不应计入相册索引
				if base == "_duplicates" || base == "_temp" {
					return filepath.SkipDir
				}
				return nil
			}

			// 必须是 YYYY/MM/DD/filename 这种结构，否则不计入索引
			relPath, _ := filepath.Rel(baseDir, path)
			slashPath := filepath.ToSlash(relPath)
			parts := strings.Split(slashPath, "/")
			if len(parts) < 4 {
				return nil
			}
			// 过滤非数字年份目录（例如误建的 1716 这种仍算数字没问题，但至少结构要对）
			dateStr := fmt.Sprintf("%s-%s-%s", parts[0], parts[1], parts[2])

			groupsMap[dateStr]++
			return nil
		})

		groups := make([]PhotoGroup, 0)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		for date, count := range groupsMap {
			groups = append(groups, PhotoGroup{
				Date:  date,
				Count: count,
			})
		}

		sort.Slice(groups, func(i, j int) bool {
			return groups[i].Date > groups[j].Date
		})

		c.JSON(http.StatusOK, groups)
	})

	// 获取指定日期的照片详情接口
	r.GET("/api/photos/detail", func(c *gin.Context) {
		dateStr := c.Query("date")
		if dateStr == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "需要提供日期参数 date"})
			return
		}

		// 解析 YYYY-MM-DD
		parts := strings.Split(dateStr, "-")
		if len(parts) != 3 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "日期格式错误，应为 YYYY-MM-DD"})
			return
		}

		targetDir := filepath.Join(baseDir, parts[0], parts[1], parts[2])
		photos := make([]PhotoInfo, 0)
		files, err := os.ReadDir(targetDir)
		if err != nil {
			c.JSON(http.StatusOK, photos)
			return
		}

		for _, f := range files {
			if f.IsDir() {
				continue
			}
			name := f.Name()
			ext := strings.ToLower(filepath.Ext(name))
			fileType := "image"
			if ext == ".mp4" || ext == ".mov" || ext == ".avi" {
				fileType = "video"
			}

			photos = append(photos, PhotoInfo{
				Name: name,
				URL:  "/public/babyphoto/" + parts[0] + "/" + parts[1] + "/" + parts[2] + "/" + name,
				Type: fileType,
			})
		}

		// 按名称排序，确保展示稳定
		sort.Slice(photos, func(i, j int) bool {
			return photos[i].Name < photos[j].Name
		})

		c.JSON(http.StatusOK, photos)
	})

	// 获取待归类文件列表
	r.GET("/api/upload/pending", func(c *gin.Context) {
		files, err := os.ReadDir(tempDir)
		if err != nil {
			c.JSON(http.StatusOK, []gin.H{})
			return
		}

		results := make([]gin.H, 0)
		for _, f := range files {
			if f.IsDir() {
				continue
			}
			name := f.Name()
			ext := strings.ToLower(filepath.Ext(name))
			fileType := "image"
			if ext == ".mp4" || ext == ".mov" || ext == ".avi" {
				fileType = "video"
			}

			hash := strings.TrimSuffix(name, ext)

			results = append(results, gin.H{
				"hash": hash,
				"ext":  ext,
				"name": name,
				"url":  "/public/babyphoto/_temp/" + name,
				"type": fileType,
			})
		}

		c.JSON(http.StatusOK, results)
	})

	// 确认归档接口
	r.POST("/api/upload/confirm", func(c *gin.Context) {
		var req struct {
			Hash string `json:"hash" binding:"required"`
			Ext  string `json:"ext" binding:"required"`
			Date string `json:"date" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数错误"})
			return
		}

		targetDate, err := time.Parse("2006-01-02", req.Date)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "日期格式错误，应为 YYYY-MM-DD"})
			return
		}

		srcPath := filepath.Join(tempDir, req.Hash+req.Ext)
		if _, err := os.Stat(srcPath); os.IsNotExist(err) {
			c.JSON(http.StatusNotFound, gin.H{"error": "找不到临时文件"})
			return
		}

		datePath := targetDate.Format("2006/01/02")
		newFileName := targetDate.Format("20060102") + "_" + req.Hash + req.Ext
		uploadDir := filepath.Join(baseDir, filepath.FromSlash(datePath))
		if err := os.MkdirAll(uploadDir, 0755); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "创建目录失败"})
			return
		}

		dstPath := filepath.Join(uploadDir, newFileName)
		if _, err := os.Stat(dstPath); err == nil {
			_ = os.Remove(srcPath)
			c.JSON(http.StatusConflict, gin.H{"error": "目标位置已存在该文件"})
			return
		}

		if err := os.Rename(srcPath, dstPath); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "移动文件失败: " + err.Error()})
			return
		}

		dupMu.Lock()
		dupIndex[req.Hash+req.Ext] = struct{}{}
		dupMu.Unlock()

		c.JSON(http.StatusOK, gin.H{
			"message": "归档成功",
			"url":     "/public/babyphoto/" + datePath + "/" + newFileName,
		})
	})

	// 取消上传接口
	r.POST("/api/upload/cancel", func(c *gin.Context) {
		var req struct {
			Hash string `json:"hash" binding:"required"`
			Ext  string `json:"ext" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数错误"})
			return
		}

		srcPath := filepath.Join(tempDir, req.Hash+req.Ext)
		if err := os.Remove(srcPath); err != nil && !os.IsNotExist(err) {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "删除失败"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "已删除"})
	})

	// 获取出生日期接口
	r.GET("/api/birthdate", func(c *gin.Context) {
		config, err := loadBabyConfig(configPath)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "读取配置失败: " + err.Error()})
			return
		}

		if config.BirthDate == "" {
			c.JSON(http.StatusOK, gin.H{"birthDate": ""})
			return
		}

		c.JSON(http.StatusOK, gin.H{"birthDate": config.BirthDate})
	})

	// 保存出生日期接口
	r.POST("/api/birthdate", func(c *gin.Context) {
		var req struct {
			BirthDate string `json:"birthDate" binding:"required"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数错误: " + err.Error()})
			return
		}

		// 验证日期格式
		_, err := time.Parse("2006-01-02", req.BirthDate)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "日期格式错误，应为 YYYY-MM-DD"})
			return
		}

		config := &BabyConfig{
			BirthDate: req.BirthDate,
		}

		if err := saveBabyConfig(configPath, config); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "保存配置失败: " + err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "保存成功", "birthDate": req.BirthDate})
	})

	// 静态文件服务
	r.Static("/public", "./public")
	// assets 目录在 public 下
	r.Static("/assets", "./public/assets")

	// 首页
	r.GET("/", func(c *gin.Context) {
		c.File("./public/index.html")
	})

	url := fmt.Sprintf("http://localhost:%d", port)
	fmt.Printf("服务启动在 %s\n", url)

	// 2. 延迟 1 秒后自动打开浏览器
	go func() {
		time.Sleep(1 * time.Second)
		openBrowser(url)
	}()

	r.Run(fmt.Sprintf(":%d", port))
}
