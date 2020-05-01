package config

import (
	"encoding/json"
	"io/ioutil"
)

type MinerConfig struct {
	PayRewardsTo string `json:"payRewardsTo"`
	RpcHost      string `json:"rpcHost"`
	RpcUser      string `json:"rpcUser"`
	RpcPassword  string `json:"rpcPassword"`
	StratumPort  int    `json:"port"`
}

func GetConfig() (MinerConfig, error) {
	var m MinerConfig
	b, err := ioutil.ReadFile("./solominer.json")
	if err != nil {
		return m, err
	}

	err = json.Unmarshal(b, &m)
	if err != nil {
		return m, err
	}
	return m, nil
}
