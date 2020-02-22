package com.example.demo.student;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("management/api/v1/students")
public class StudentManagementController {

    private static final List<Student> STUDENTS = Arrays.asList(
            new Student(1, "James Bond"),
            new Student(2, "Maria Jones"),
            new Student(3, "Anna Smith")
    );

    @GetMapping
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_ADMIN_TRAINEE')")
    public List<Student> getAllStudents() {
        return STUDENTS;
    }

    @PostMapping
    public void registerNewStudent(@RequestBody Student student) {
        System.out.println("Post " + student);
//        STUDENTS.add(new Student(STUDENTS.size(), student.getStudentName()));
    }

    @DeleteMapping(path = "{studentId}")
    @PreAuthorize("hasAuthority('course:write')")
    public void deleteStudent(@PathVariable Integer studentId) {
        System.out.println("Delete " + studentId);
//        STUDENTS.removeIf(s -> s.getStudentId() == studentId);
    }

    @PutMapping(path = "{studentId}")
    public void updateStudent(@PathVariable final Integer studentId, @RequestBody Student student) {
        System.out.println(String.format("Put %s, id - %s", student, studentId));
//        if (STUDENTS.removeIf(s -> s.getStudentId() == studentId)) {
//            STUDENTS.add(new Student(studentId, student.getStudentName()));
//        }
    }
}
