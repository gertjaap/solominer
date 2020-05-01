# Solominer

This project allows you to solomine using Vertcoin Core.

If you want to support this development, you can donate Vertcoin to `VrbZFZHYWSoKRuZW5VFxgL5HL9QhLy4yvr`.

## How to build

```
go get github.com/gertjaap/solominer
cd $GOPATH/src/github.com/gertjaap/solominer
go get ./...
go build
```

## How to run

Ensure all parameters are properly set in `solominer.json`, like the RPC host, credentials, and the address to pay out to.

Then start the miner with 

```
cd $GOPATH/src/github.com/gertjaap/solominer
./solominer
```

