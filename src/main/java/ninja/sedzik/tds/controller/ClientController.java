package ninja.sedzik.tds.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@Controller
@RequestMapping("/client")
public class ClientController {


    @RequestMapping("/one")
    @ResponseBody
    private String dupa(){
        return "client";
    }
}
