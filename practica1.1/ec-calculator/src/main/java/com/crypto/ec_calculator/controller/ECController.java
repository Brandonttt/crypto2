package com.crypto.ec_calculator.controller;

import com.crypto.ec_calculator.dto.ECDTOs.*;
import com.crypto.ec_calculator.service.ECService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.math.BigInteger;

@RestController
@RequestMapping("/api/ec")
@CrossOrigin(origins = "*")
public class ECController {

    private final ECService ecService;

    public ECController(ECService ecService) {
        this.ecService = ecService;
    }

    @PostMapping("/validate")
    public ResponseEntity<ValidationResponse> validate(@RequestBody CurveParams params) {
        return ResponseEntity.ok(ecService.validateCurve(params));
    }

    @GetMapping("/analyze")
    public ResponseEntity<AnalysisResponse> analyze(
            @RequestParam BigInteger a,
            @RequestParam BigInteger b,
            @RequestParam BigInteger p) {
        return ResponseEntity.ok(ecService.analyzeGroup(new CurveParams(a, b, p)));
    }

    @PostMapping("/add")
    public ResponseEntity<OperationResponse> add(@RequestBody OperationRequest req) {
        return ResponseEntity.ok(ecService.addPoints(req.curve(), req.p1(), req.p2()));
    }

    @PostMapping("/multiply")
    public ResponseEntity<ScalarMultiplyResponse> multiply(@RequestBody ScalarMultiplyRequest req) {
        return ResponseEntity.ok(ecService.multiply(req.curve(), req.point(), req.k()));
    }

    @GetMapping("/table/addition")
    public ResponseEntity<AdditionTableResponse> additionTable(
            @RequestParam BigInteger a,
            @RequestParam BigInteger b,
            @RequestParam BigInteger p) {
        return ResponseEntity.ok(ecService.getAdditionTable(new CurveParams(a, b, p)));
    }

    @GetMapping("/table/multiplication")
    public ResponseEntity<MultiplicationTableResponse> multiplicationTable(
            @RequestParam BigInteger a,
            @RequestParam BigInteger b,
            @RequestParam BigInteger p) {
        return ResponseEntity.ok(ecService.getMultiplicationTable(new CurveParams(a, b, p)));
    }
}