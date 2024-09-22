package com.example.authenticationdemo;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
public class WebController {

    @GetMapping("/public")
    public String publicResource(){
        return "this is a public resource";
    }

    @GetMapping("/private")
    public String privateResource() {
        return "this is a private resource";
    }

    @GetMapping("/error")
    public String getError() {
        return "got error";
    }
}
