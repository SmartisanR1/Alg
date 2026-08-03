//go:build ignore

// FALCON KAT 向量自检工具。
//
// 运行方式（在 _probe 目录）:
//   go run main2.go
//
// 读取 ../testdata/falcon512_vec.txt 并逐条校验:
//   1) 由私钥派生公钥是否与向量公钥一致
//   2) 官方签名对对应消息验签是否通过
//   3) 篡改消息验签是否失败
package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	falcon "github.com/lattice-safe/falcon-go"
)

func main() {
	f, err := os.Open("../testdata/falcon512_vec.txt")
	if err != nil {
		fmt.Println("打开向量文件失败:", err)
		os.Exit(1)
	}
	defer f.Close()

	var pk, sk, sig, msg []byte
	idx := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, "TEST"):
			idx++
			msg, pk, sk, sig = nil, nil, nil, nil
		case strings.HasPrefix(line, "msg="):
			msg, _ = hex.DecodeString(strings.TrimPrefix(line, "msg="))
		case strings.HasPrefix(line, "pk="):
			pk, _ = hex.DecodeString(strings.TrimPrefix(line, "pk="))
		case strings.HasPrefix(line, "sk="):
			sk, _ = hex.DecodeString(strings.TrimPrefix(line, "sk="))
		case strings.HasPrefix(line, "sig="):
			sig, _ = hex.DecodeString(strings.TrimPrefix(line, "sig="))
		case strings.HasPrefix(line, "verify="):
			derived, derr := falcon.PublicKeyFromPrivate(sk)
			pkMatch := derr == nil && hex.EncodeToString(derived) == hex.EncodeToString(pk)
			ok := falcon.Verify(sig, pk, msg, falcon.DomainNone()) == nil
			bad := falcon.Verify(sig, pk, append(append([]byte{}, msg...), 0), falcon.DomainNone()) == nil
			fmt.Printf("TEST %d: pk=%dB sk=%dB sig=%dB msg=%dB pk派生=%v 验签=%v 篡改拒签=%v\n",
				idx, len(pk), len(sk), len(sig), len(msg), pkMatch, ok, !bad)
		}
	}
}
