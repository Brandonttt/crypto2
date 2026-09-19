package com.crypto.ec_calculator.controller;

import com.crypto.ec_calculator.dto.ECDTOs.*;
import com.crypto.ec_calculator.service.ECService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.math.BigInteger;
import java.util.List;

@RestController
@RequestMapping("/api/ec")
@CrossOrigin(origins = "*") // Ajustar según el origen del frontend
public class ECController {

    private final ECService ecService;

    public ECController(ECService ecService) {
        this.ecService = ecService;
    }

    @PostMapping("/validate")
    public ResponseEntity<ValidationResponse> validate(@RequestBody CurveParams params) {
        return ResponseEntity.ok(ecService.validateCurve(params));
    }

    @GetMapping("/points")
    public ResponseEntity<List<PointDTO>> getPoints(
            @RequestParam BigInteger a,
            @RequestParam BigInteger b,
            @RequestParam BigInteger p) {
        return ResponseEntity.ok(ecService.getAllPoints(new CurveParams(a, b, p)));
    }

    @PostMapping("/add")
    public ResponseEntity<AddPointsResponse> addPoints(@RequestBody AddPointsRequest request) {
        return ResponseEntity.ok(ecService.addPoints(request));
    }

    @PostMapping("/multiply")
    public ResponseEntity<MultiplyResponse> multiply(@RequestBody MultiplyRequest request) {
        return ResponseEntity.ok(ecService.multiply(request));
    }

    @GetMapping("/order")
    public ResponseEntity<GroupOrderResponse> getGroupOrder(
            @RequestParam BigInteger a,
            @RequestParam BigInteger b,
            @RequestParam BigInteger p) {
        List<PointDTO> points = ecService.getAllPoints(new CurveParams(a, b, p));
        // +1 contando el punto al infinito
        return ResponseEntity.ok(new GroupOrderResponse(points.size() + 1, points));
    }
}