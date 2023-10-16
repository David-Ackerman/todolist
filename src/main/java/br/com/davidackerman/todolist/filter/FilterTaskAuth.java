package br.com.davidackerman.todolist.filter;

import java.io.IOException;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import at.favre.lib.crypto.bcrypt.BCrypt;
import br.com.davidackerman.todolist.user.IUserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class FilterTaskAuth extends OncePerRequestFilter {

  @Autowired
  private IUserRepository userRepository;

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {

    var serveletPath = request.getServletPath();

    if (!serveletPath.startsWith("/tasks/")) {
      filterChain.doFilter(request, response);
      return;
    }

    var authorization = request.getHeader("Authorization");

    var authDecoded = authorization.substring("Basic ".length()).trim();

    byte[] authDecode = Base64.getDecoder().decode(authDecoded);

    var authString = new String(authDecode);
    String[] credentials = authString.split(":");
    String username = credentials[0];
    String password = credentials[1];

    var user = this.userRepository.findByUsername(username);

    if (user == null) {
      response.sendError(401);
      return;
    }
    var passwordVerify = BCrypt.verifyer().verify(password.toCharArray(), user.getPassword());
    if (!passwordVerify.verified) {
      response.sendError(401);
      return;
    }
    request.setAttribute("userId", user.getId());
    filterChain.doFilter(request, response);

  }

}
