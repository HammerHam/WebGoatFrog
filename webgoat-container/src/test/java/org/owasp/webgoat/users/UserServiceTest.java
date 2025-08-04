package org.owasp.webgoat.users;

import org.assertj.core.api.Assertions;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Arrays;
import java.util.List;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    @Mock
    private UserRepository userRepository;
    @Mock
    private UserTrackerRepository userTrackerRepository;
    @Mock
    private JdbcTemplate jdbcTemplate;
    @Mock
    private Function<String, Flyway> flywayLessons;

    private UserService userService;

    @BeforeEach
    void setUp() {
        userService = new UserService(userRepository, userTrackerRepository, jdbcTemplate, flywayLessons);
    }

    @Nested
    @DisplayName("loadUserByUsername Tests")
    class LoadUserByUsernameTests {

        @Test
        @DisplayName("Should throw exception when user is not found")
        void shouldThrowExceptionWhenUserIsNotFound() {
            // Given
            when(userRepository.findByUsername(any())).thenReturn(null);
            
            // When & Then
            assertThatThrownBy(() -> userService.loadUserByUsername("unknown"))
                    .isInstanceOf(UsernameNotFoundException.class)
                    .hasMessage("User not found");
            
            verify(userRepository).findByUsername("unknown");
        }

        @Test
        @DisplayName("Should return WebGoatUser when user exists and call createUser")
        void shouldReturnWebGoatUserWhenUserExistsAndCallCreateUser() {
            // Given
            String username = "testuser";
            WebGoatUser mockUser = spy(new WebGoatUser(username, "password"));
            when(userRepository.findByUsername(username)).thenReturn(mockUser);

            // When
            WebGoatUser result = userService.loadUserByUsername(username);

            // Then
            assertThat(result).isNotNull();
            assertThat(result.getUsername()).isEqualTo(username);
            assertThat(result.getPassword()).isEqualTo("password");
            verify(userRepository).findByUsername(username);
            verify(mockUser).createUser();
        }

        @Test
        @DisplayName("Should throw exception when username is null")
        void shouldThrowExceptionWhenUsernameIsNull() {
            // Given
            when(userRepository.findByUsername(null)).thenReturn(null);
            
            // When & Then
            assertThatThrownBy(() -> userService.loadUserByUsername(null))
                    .isInstanceOf(UsernameNotFoundException.class)
                    .hasMessage("User not found");
            
            verify(userRepository).findByUsername(null);
        }

        @Test
        @DisplayName("Should throw exception when username is empty")
        void shouldThrowExceptionWhenUsernameIsEmpty() {
            // Given
            when(userRepository.findByUsername("")).thenReturn(null);
            
            // When & Then
            assertThatThrownBy(() -> userService.loadUserByUsername(""))
                    .isInstanceOf(UsernameNotFoundException.class)
                    .hasMessage("User not found");
            
            verify(userRepository).findByUsername("");
        }

        @Test
        @DisplayName("Should handle special characters in username")
        void shouldHandleSpecialCharactersInUsername() {
            // Given
            String specialUsername = "user@#$%^&*()";
            WebGoatUser user = spy(new WebGoatUser(specialUsername, "password"));
            when(userRepository.findByUsername(specialUsername)).thenReturn(user);

            // When
            WebGoatUser result = userService.loadUserByUsername(specialUsername);

            // Then
            assertThat(result).isNotNull();
            assertThat(result.getUsername()).isEqualTo(specialUsername);
            verify(user).createUser();
        }

        @Test
        @DisplayName("Should handle whitespace in username")
        void shouldHandleWhitespaceInUsername() {
            // Given
            String whitespaceUsername = "  user with spaces  ";
            WebGoatUser user = spy(new WebGoatUser(whitespaceUsername, "password"));
            when(userRepository.findByUsername(whitespaceUsername)).thenReturn(user);

            // When
            WebGoatUser result = userService.loadUserByUsername(whitespaceUsername);

            // Then
            assertThat(result).isNotNull();
            assertThat(result.getUsername()).isEqualTo(whitespaceUsername);
            verify(user).createUser();
        }

        @Test
        @DisplayName("Should handle very long username")
        void shouldHandleVeryLongUsername() {
            // Given
            String longUsername = "a".repeat(1000);
            when(userRepository.findByUsername(longUsername)).thenReturn(null);

            // When & Then
            assertThatThrownBy(() -> userService.loadUserByUsername(longUsername))
                    .isInstanceOf(UsernameNotFoundException.class)
                    .hasMessage("User not found");
        }

        @Test
        @DisplayName("Should handle username with Unicode characters")
        void shouldHandleUsernameWithUnicodeCharacters() {
            // Given
            String unicodeUsername = "用户名测试αβγ";
            WebGoatUser user = spy(new WebGoatUser(unicodeUsername, "password"));
            when(userRepository.findByUsername(unicodeUsername)).thenReturn(user);

            // When
            WebGoatUser result = userService.loadUserByUsername(unicodeUsername);

            // Then
            assertThat(result).isNotNull();
            assertThat(result.getUsername()).isEqualTo(unicodeUsername);
            verify(user).createUser();
        }
    }

    @Nested
    @DisplayName("addUser Tests")
    class AddUserTests {

        @Test
        @DisplayName("Should create user tracker and lessons when user does not exist")
        void shouldCreateUserTrackerAndLessonsWhenUserDoesNotExist() {
            // Given
            String username = "newuser";
            String password = "password123";
            WebGoatUser savedUser = new WebGoatUser(username, password);
            when(userRepository.existsByUsername(username)).thenReturn(false);
            when(userRepository.save(any(WebGoatUser.class))).thenReturn(savedUser);
            
            Flyway mockFlyway = mock(Flyway.class);
            when(flywayLessons.apply(username)).thenReturn(mockFlyway);

            // When
            userService.addUser(username, password);

            // Then
            verify(userRepository).existsByUsername(username);
            verify(userRepository).save(any(WebGoatUser.class));
            verify(userTrackerRepository).save(any(UserTracker.class));
            verify(jdbcTemplate).execute(eq("CREATE SCHEMA \"" + username + "\" authorization dba"));
            verify(flywayLessons).apply(username);
            verify(mockFlyway).migrate();
        }

        @Test
        @DisplayName("Should not create user tracker and lessons when user already exists")
        void shouldNotCreateUserTrackerAndLessonsWhenUserAlreadyExists() {
            // Given
            String username = "existinguser";
            String password = "password123";
            WebGoatUser savedUser = new WebGoatUser(username, password);
            when(userRepository.existsByUsername(username)).thenReturn(true);
            when(userRepository.save(any(WebGoatUser.class))).thenReturn(savedUser);

            // When
            userService.addUser(username, password);

            // Then
            verify(userRepository).existsByUsername(username);
            verify(userRepository).save(any(WebGoatUser.class)); // User is still saved
            verify(userTrackerRepository, never()).save(any(UserTracker.class));
            verify(jdbcTemplate, never()).execute(anyString());
            verify(flywayLessons, never()).apply(anyString());
        }

        @Test
        @DisplayName("Should handle null username")
        void shouldHandleNullUsername() {
            // Given
            WebGoatUser savedUser = new WebGoatUser(null, "password");
            when(userRepository.existsByUsername(null)).thenReturn(false);
            when(userRepository.save(any(WebGoatUser.class))).thenReturn(savedUser);
            
            Flyway mockFlyway = mock(Flyway.class);
            when(flywayLessons.apply(null)).thenReturn(mockFlyway);

            // When
            userService.addUser(null, "password");

            // Then
            verify(userRepository).existsByUsername(null);
            verify(userRepository).save(any(WebGoatUser.class));
            verify(userTrackerRepository).save(any(UserTracker.class));
            verify(jdbcTemplate).execute(eq("CREATE SCHEMA \"" + null + "\" authorization dba"));
            verify(flywayLessons).apply(null);
            verify(mockFlyway).migrate();
        }

        @Test
        @DisplayName("Should handle null password")
        void shouldHandleNullPassword() {
            // Given
            String username = "testuser";
            WebGoatUser savedUser = new WebGoatUser(username, null);
            when(userRepository.existsByUsername(username)).thenReturn(false);
            when(userRepository.save(any(WebGoatUser.class))).thenReturn(savedUser);
            
            Flyway mockFlyway = mock(Flyway.class);
            when(flywayLessons.apply(username)).thenReturn(mockFlyway);

            // When
            userService.addUser(username, null);

            // Then
            verify(userRepository).existsByUsername(username);
            verify(userRepository).save(any(WebGoatUser.class));
            verify(userTrackerRepository).save(any(UserTracker.class));
            verify(jdbcTemplate).execute(eq("CREATE SCHEMA \"" + username + "\" authorization dba"));
            verify(flywayLessons).apply(username);
            verify(mockFlyway).migrate();
        }

        @Test
        @DisplayName("Should handle empty username")
        void shouldHandleEmptyUsername() {
            // Given
            String emptyUsername = "";
            WebGoatUser savedUser = new WebGoatUser(emptyUsername, "password");
            when(userRepository.existsByUsername(emptyUsername)).thenReturn(false);
            when(userRepository.save(any(WebGoatUser.class))).thenReturn(savedUser);
            
            Flyway mockFlyway = mock(Flyway.class);
            when(flywayLessons.apply(emptyUsername)).thenReturn(mockFlyway);

            // When
            userService.addUser(emptyUsername, "password");

            // Then
            verify(userRepository).existsByUsername(emptyUsername);
            verify(userRepository).save(any(WebGoatUser.class));
            verify(userTrackerRepository).save(any(UserTracker.class));
            verify(jdbcTemplate).execute(eq("CREATE SCHEMA \"" + emptyUsername + "\" authorization dba"));
            verify(flywayLessons).apply(emptyUsername);
            verify(mockFlyway).migrate();
        }

        @Test
        @DisplayName("Should handle special characters in database schema creation")
        void shouldHandleSpecialCharactersInDatabaseSchemaCreation() {
            // Given
            String specialUsername = "user@test";
            String password = "password123";
            WebGoatUser savedUser = new WebGoatUser(specialUsername, password);
            when(userRepository.existsByUsername(specialUsername)).thenReturn(false);
            when(userRepository.save(any(WebGoatUser.class))).thenReturn(savedUser);
            
            Flyway mockFlyway = mock(Flyway.class);
            when(flywayLessons.apply(specialUsername)).thenReturn(mockFlyway);

            // When
            userService.addUser(specialUsername, password);

            // Then
            verify(userRepository).existsByUsername(specialUsername);
            verify(userRepository).save(any(WebGoatUser.class));
            verify(userTrackerRepository).save(any(UserTracker.class));
            verify(jdbcTemplate).execute(eq("CREATE SCHEMA \"" + specialUsername + "\" authorization dba"));
            verify(flywayLessons).apply(specialUsername);
            verify(mockFlyway).migrate();
        }
    }

    @Nested
    @DisplayName("getAllUsers Tests")
    class GetAllUsersTests {

        @Test
        @DisplayName("Should return all users from repository")
        void shouldReturnAllUsersFromRepository() {
            // Given
            List<WebGoatUser> expectedUsers = Arrays.asList(
                new WebGoatUser("user1", "password1"),
                new WebGoatUser("user2", "password2"),
                new WebGoatUser("user3", "password3")
            );
            when(userRepository.findAll()).thenReturn(expectedUsers);

            // When
            List<WebGoatUser> result = userService.getAllUsers();

            // Then
            assertThat(result).isNotNull();
            assertThat(result).hasSize(3);
            assertThat(result).containsExactlyElementsOf(expectedUsers);
            verify(userRepository).findAll();
        }

        @Test
        @DisplayName("Should return empty list when no users exist")
        void shouldReturnEmptyListWhenNoUsersExist() {
            // Given
            when(userRepository.findAll()).thenReturn(Arrays.asList());

            // When
            List<WebGoatUser> result = userService.getAllUsers();

            // Then
            assertThat(result).isNotNull();
            assertThat(result).isEmpty();
            verify(userRepository).findAll();
        }

        @Test
        @DisplayName("Should handle repository returning null")
        void shouldHandleRepositoryReturningNull() {
            // Given
            when(userRepository.findAll()).thenReturn(null);

            // When
            List<WebGoatUser> result = userService.getAllUsers();

            // Then
            assertThat(result).isNull();
            verify(userRepository).findAll();
        }

        @Test
        @DisplayName("Should handle repository throwing exception")
        void shouldHandleRepositoryThrowingException() {
            // Given
            when(userRepository.findAll()).thenThrow(new RuntimeException("Database connection failed"));

            // When & Then
            assertThatThrownBy(() -> userService.getAllUsers())
                    .isInstanceOf(RuntimeException.class)
                    .hasMessage("Database connection failed");
            
            verify(userRepository).findAll();
        }
    }

    @Nested
    @DisplayName("Error Handling and Edge Cases")
    class ErrorHandlingAndEdgeCasesTests {

        @Test
        @DisplayName("Should handle database exception during schema creation")
        void shouldHandleDatabaseExceptionDuringSchemaCreation() {
            // Given
            String username = "testuser";
            String password = "password123";
            WebGoatUser savedUser = new WebGoatUser(username, password);
            when(userRepository.existsByUsername(username)).thenReturn(false);
            when(userRepository.save(any(WebGoatUser.class))).thenReturn(savedUser);
            doThrow(new RuntimeException("Schema creation failed")).when(jdbcTemplate).execute(anyString());

            // When & Then
            assertThatThrownBy(() -> userService.addUser(username, password))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessage("Schema creation failed");
            
            verify(userRepository).existsByUsername(username);
            verify(userRepository).save(any(WebGoatUser.class));
            verify(userTrackerRepository).save(any(UserTracker.class));
            verify(jdbcTemplate).execute(eq("CREATE SCHEMA \"" + username + "\" authorization dba"));
        }

        @Test
        @DisplayName("Should handle flyway migration failure")
        void shouldHandleFlywayMigrationFailure() {
            // Given
            String username = "testuser";
            String password = "password123";
            WebGoatUser savedUser = new WebGoatUser(username, password);
            when(userRepository.existsByUsername(username)).thenReturn(false);
            when(userRepository.save(any(WebGoatUser.class))).thenReturn(savedUser);
            
            Flyway mockFlyway = mock(Flyway.class);
            when(flywayLessons.apply(username)).thenReturn(mockFlyway);
            doThrow(new RuntimeException("Migration failed")).when(mockFlyway).migrate();

            // When & Then
            assertThatThrownBy(() -> userService.addUser(username, password))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessage("Migration failed");
            
            verify(userRepository).existsByUsername(username);
            verify(userRepository).save(any(WebGoatUser.class));
            verify(userTrackerRepository).save(any(UserTracker.class));
            verify(jdbcTemplate).execute(eq("CREATE SCHEMA \"" + username + "\" authorization dba"));
            verify(flywayLessons).apply(username);
            verify(mockFlyway).migrate();
        }

        @Test
        @DisplayName("Should handle userRepository save failure")
        void shouldHandleUserRepositorySaveFailure() {
            // Given
            String username = "testuser";
            String password = "password123";
            when(userRepository.existsByUsername(username)).thenReturn(false);
            when(userRepository.save(any(WebGoatUser.class))).thenThrow(new RuntimeException("Save failed"));

            // When & Then
            assertThatThrownBy(() -> userService.addUser(username, password))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessage("Save failed");
            
            verify(userRepository).existsByUsername(username);
            verify(userRepository).save(any(WebGoatUser.class));
        }

        @Test
        @DisplayName("Should handle userTrackerRepository save failure")
        void shouldHandleUserTrackerRepositorySaveFailure() {
            // Given
            String username = "testuser";
            String password = "password123";
            WebGoatUser savedUser = new WebGoatUser(username, password);
            when(userRepository.existsByUsername(username)).thenReturn(false);
            when(userRepository.save(any(WebGoatUser.class))).thenReturn(savedUser);
            when(userTrackerRepository.save(any(UserTracker.class))).thenThrow(new RuntimeException("Tracker save failed"));

            // When & Then
            assertThatThrownBy(() -> userService.addUser(username, password))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessage("Tracker save failed");
            
            verify(userRepository).existsByUsername(username);
            verify(userRepository).save(any(WebGoatUser.class));
            verify(userTrackerRepository).save(any(UserTracker.class));
        }

        @Test
        @DisplayName("Should handle concurrent calls to loadUserByUsername")
        void shouldHandleConcurrentCallsToLoadUserByUsername() {
            // Given
            String username = "concurrentuser";
            WebGoatUser user = spy(new WebGoatUser(username, "password"));
            when(userRepository.findByUsername(username)).thenReturn(user);

            // When - simulate concurrent calls
            WebGoatUser result1 = userService.loadUserByUsername(username);
            WebGoatUser result2 = userService.loadUserByUsername(username);

            // Then
            assertThat(result1).isNotNull();
            assertThat(result2).isNotNull();
            assertThat(result1.getUsername()).isEqualTo(username);
            assertThat(result2.getUsername()).isEqualTo(username);
            verify(userRepository, times(2)).findByUsername(username);
            verify(user, times(2)).createUser();
        }
    }

    @Nested
    @DisplayName("Integration Scenarios")
    class IntegrationScenariosTests {

        @Test
        @DisplayName("Should handle complete user lifecycle operations")
        void shouldHandleCompleteUserLifecycleOperations() {
            // Given
            String username = "lifecycleuser";
            String password = "password123";
            WebGoatUser savedUser = spy(new WebGoatUser(username, password));
            when(userRepository.existsByUsername(username)).thenReturn(false);
            when(userRepository.save(any(WebGoatUser.class))).thenReturn(savedUser);
            when(userRepository.findByUsername(username)).thenReturn(savedUser);
            when(userRepository.findAll()).thenReturn(Arrays.asList(savedUser));
            
            Flyway mockFlyway = mock(Flyway.class);
            when(flywayLessons.apply(username)).thenReturn(mockFlyway);

            // When - Add user
            userService.addUser(username, password);
            // When - Load user
            WebGoatUser loadedUser = userService.loadUserByUsername(username);
            // When - Get all users
            List<WebGoatUser> allUsers = userService.getAllUsers();

            // Then - Verify all operations
            verify(userRepository).existsByUsername(username);
            verify(userRepository).save(any(WebGoatUser.class));
            verify(userTrackerRepository).save(any(UserTracker.class));
            verify(jdbcTemplate).execute(eq("CREATE SCHEMA \"" + username + "\" authorization dba"));
            verify(flywayLessons).apply(username);
            verify(mockFlyway).migrate();
            verify(userRepository).findByUsername(username);
            verify(savedUser).createUser();
            verify(userRepository).findAll();
            
            assertThat(loadedUser).isNotNull();
            assertThat(loadedUser.getUsername()).isEqualTo(username);
            assertThat(allUsers).hasSize(1);
            assertThat(allUsers.get(0).getUsername()).isEqualTo(username);
        }

        @Test
        @DisplayName("Should handle multiple user creation scenarios")
        void shouldHandleMultipleUserCreationScenarios() {
            // Given
            String existingUsername = "existinguser";
            String newUsername = "newuser";
            String password = "password123";
            
            WebGoatUser existingUser = new WebGoatUser(existingUsername, password);
            WebGoatUser newUser = new WebGoatUser(newUsername, password);
            
            when(userRepository.existsByUsername(existingUsername)).thenReturn(true);
            when(userRepository.existsByUsername(newUsername)).thenReturn(false);
            when(userRepository.save(any(WebGoatUser.class))).thenReturn(existingUser, newUser);
            
            Flyway mockFlyway = mock(Flyway.class);
            when(flywayLessons.apply(newUsername)).thenReturn(mockFlyway);

            // When
            userService.addUser(existingUsername, password);
            userService.addUser(newUsername, password);

            // Then
            verify(userRepository).existsByUsername(existingUsername);
            verify(userRepository).existsByUsername(newUsername);
            verify(userRepository, times(2)).save(any(WebGoatUser.class));
            verify(userTrackerRepository, times(1)).save(any(UserTracker.class)); // Only for new user
            verify(jdbcTemplate, times(1)).execute(anyString()); // Only for new user
            verify(flywayLessons, times(1)).apply(newUsername); // Only for new user
            verify(mockFlyway, times(1)).migrate(); // Only for new user
        }
    }
}