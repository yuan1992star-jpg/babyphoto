package main

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
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
	Photos []PhotoInfo `json:"photos"`
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

// 在整个目录中查找是否存在相同哈希值的文件
func findDuplicateFile(baseDir, fileHash, ext string) (string, bool) {
	var foundPath string
	filepath.Walk(baseDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			// 跳过重复文件目录
			if strings.Contains(path, "_duplicates") {
				return filepath.SkipDir
			}
			return nil
		}
		// 检查文件名是否以相同的哈希值开头
		if strings.HasPrefix(info.Name(), fileHash) {
			foundPath = path
			return filepath.SkipAll // 找到后停止搜索
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
	// 配置文件路径
	configPath := "./baby_config.json"

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

		var results []gin.H

		for _, file := range files {
			src, err := file.Open()
			if err != nil {
				results = append(results, gin.H{"filename": file.Filename, "status": "fail", "error": "无法打开文件"})
				continue
			}

			// 1. 尝试读取拍摄日期 (EXIF)
			shootingDate := getShootingDate(src)
			// 重置文件流
			if seeker, ok := src.(io.Seeker); ok {
				seeker.Seek(0, 0)
			}

			// 2. 计算 MD5 去重
			hash := md5.New()
			if _, err := io.Copy(hash, src); err != nil {
				src.Close()
				results = append(results, gin.H{"filename": file.Filename, "status": "fail", "error": "哈希计算失败"})
				continue
			}
			fileHash := fmt.Sprintf("%x", hash.Sum(nil))
			ext := strings.ToLower(filepath.Ext(file.Filename))
			newFileName := fileHash + ext

			// 3. 确定存储路径：优先使用拍摄日期
			var targetDate time.Time
			if !shootingDate.IsZero() {
				targetDate = shootingDate
			} else {
				targetDate = time.Now()
			}

			datePath := filepath.Join(targetDate.Format("2006"), targetDate.Format("01"), targetDate.Format("02"))
			uploadDir := filepath.Join(baseDir, datePath)

			// 确保目录存在
			if err := os.MkdirAll(uploadDir, 0755); err != nil {
				src.Close()
				results = append(results, gin.H{"filename": file.Filename, "status": "fail", "error": "创建目录失败"})
				continue
			}

			dstPath := filepath.Join(uploadDir, newFileName)
			relURL := "/public/babyphoto/" + filepath.ToSlash(filepath.Join(datePath, newFileName))

			// 4. 检查文件是否已存在（先检查当前目录，再全局搜索）
			isDuplicate := false
			duplicateDir := filepath.Join(baseDir, "_duplicates")
			
			// 先检查当前日期目录
			if _, err := os.Stat(dstPath); err == nil {
				isDuplicate = true
			} else {
				// 全局搜索重复文件
				_, isDuplicate = findDuplicateFile(baseDir, fileHash, ext)
			}

			if isDuplicate {
				// 重复文件：移动到 _duplicates 目录
				if err := os.MkdirAll(duplicateDir, 0755); err != nil {
					src.Close()
					results = append(results, gin.H{"filename": file.Filename, "status": "fail", "error": "创建重复文件目录失败"})
					continue
				}

				// 使用原始文件名+时间戳+哈希值命名，避免文件名冲突
				timestamp := time.Now().Format("20060102_150405")
				baseName := strings.TrimSuffix(file.Filename, ext)
				duplicateFileName := fmt.Sprintf("%s_%s_%s%s", baseName, timestamp, fileHash[:8], ext)
				duplicatePath := filepath.Join(duplicateDir, duplicateFileName)
				duplicateURL := "/public/babyphoto/_duplicates/" + duplicateFileName

				if _, err := src.Seek(0, 0); err != nil {
					src.Close()
					results = append(results, gin.H{"filename": file.Filename, "status": "fail", "error": "文件重置失败"})
					continue
				}

				out, err := os.Create(duplicatePath)
				if err != nil {
					src.Close()
					results = append(results, gin.H{"filename": file.Filename, "status": "fail", "error": "创建重复文件失败"})
					continue
				}

				_, err = io.Copy(out, src)
				out.Close()
				src.Close()

				if err != nil {
					results = append(results, gin.H{"filename": file.Filename, "status": "fail", "error": "保存重复文件失败"})
					continue
				}

				results = append(results, gin.H{
					"filename": file.Filename,
					"status":   "duplicate",
					"message":  "检测到重复文件，已移动到重复目录",
					"url":      duplicateURL,
				})
				continue
			}

			if _, err := src.Seek(0, 0); err != nil {
				src.Close()
				results = append(results, gin.H{"filename": file.Filename, "status": "fail", "error": "文件重置失败"})
				continue
			}

			out, err := os.Create(dstPath)
			if err != nil {
				src.Close()
				results = append(results, gin.H{"filename": file.Filename, "status": "fail", "error": "创建目标文件失败"})
				continue
			}

			_, err = io.Copy(out, src)
			out.Close()
			src.Close()

			if err != nil {
				results = append(results, gin.H{"filename": file.Filename, "status": "fail", "error": "保存失败"})
				continue
			}

			results = append(results, gin.H{
				"filename": file.Filename,
				"status":   "success",
				"url":      relURL,
			})
		}

		c.JSON(http.StatusOK, gin.H{
			"message": fmt.Sprintf("处理完成，共 %d 个文件", len(files)),
			"results": results,
		})
	})

	// 获取所有照片接口
	r.GET("/api/photos", func(c *gin.Context) {
		groupsMap := make(map[string][]PhotoInfo)

		err := filepath.Walk(baseDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				// 跳过重复文件目录
				if strings.Contains(path, "_duplicates") {
					return filepath.SkipDir
				}
				return nil
			}

			// 获取相对于 baseDir 的路径
			relPath, _ := filepath.Rel(baseDir, path)
			slashPath := filepath.ToSlash(relPath)
			parts := strings.Split(slashPath, "/")

			var dateStr string
			// 逻辑优化：如果是 YYYY/MM/DD/file 格式
			if len(parts) >= 4 {
				dateStr = fmt.Sprintf("%s-%s-%s", parts[0], parts[1], parts[2])
			} else {
				// 如果是老文件或格式不对，使用文件修改日期
				dateStr = info.ModTime().Format("2006-01-02")
			}

			ext := strings.ToLower(filepath.Ext(path))
			fileType := "image"
			if ext == ".mp4" || ext == ".mov" || ext == ".avi" {
				fileType = "video"
			}

			groupsMap[dateStr] = append(groupsMap[dateStr], PhotoInfo{
				Name: info.Name(),
				URL:  "/public/babyphoto/" + slashPath,
				Type: fileType,
			})
			return nil
		})

		// 关键点：初始化为长度为 0 的空切片，保证 JSON 返回 []
		groups := make([]PhotoGroup, 0)

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		for date, photos := range groupsMap {
			groups = append(groups, PhotoGroup{
				Date:   date,
				Photos: photos,
			})
		}

		// 按日期倒序排序
		sort.Slice(groups, func(i, j int) bool {
			return groups[i].Date > groups[j].Date
		})

		c.JSON(http.StatusOK, groups)
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

