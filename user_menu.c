#include <menu.h>
#include <ncurses.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "user_menu.h"
#include "pass_manager.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))

char* action_choices[] = {"Encrypt", "Decrypt"};
char* key_choices[] = {"128 bit", "192 bit", "256 bit"};

key_size_t get_key_size()
{
  int c;
  key_size_t key_size;
  WINDOW* window = newwin(0, 0, 0, 0);

  int n_choices = ARRAY_SIZE(key_choices);
  ITEM** items = (ITEM **)calloc(n_choices + 1, sizeof(ITEM *));
  for (int counter = 0; counter < n_choices; ++counter)
  {
    items[counter] = new_item(key_choices[counter], NULL);
  }

  MENU* key_menu = new_menu((ITEM **)items);
  WINDOW* key_menu_win = newwin(10, 40, 0, 0);
  set_menu_win(key_menu, key_menu_win);
  set_menu_sub(key_menu, derwin(key_menu_win, 10, 40, 0, 0));

  set_menu_mark(key_menu, " * ");

  post_menu(key_menu);
  wrefresh(key_menu_win);

  while ((c = getch()) != KEY_F(1)) 
  {
    switch (c) 
    {
    case KEY_DOWN:
      menu_driver(key_menu, REQ_DOWN_ITEM);
      break;
    case KEY_UP:
      menu_driver(key_menu, REQ_UP_ITEM);
      break;
    case 10:
      {
        int counter = item_index(current_item(key_menu));
        if (counter == 0)
        {
          key_size = aes_128_bit;
        }
        else if (counter == 1)
        {
          key_size = aes_192_bit;
        }
        else if (counter == 2)
        {
          key_size = aes_256_bit;
        }

        goto exit;
      }
    }

    wrefresh(key_menu_win);
  }

  return 0;

  exit:
  free_item(items[0]);
  free_item(items[1]);
  free_item(items[2]);
  free_menu(key_menu);
  delwin(key_menu_win);

  return key_size;
}

void menu_encrypt_clbk() 
{
  encrypted_pass_t* encrypted_pass = NULL;
  pass_t* pass_data = NULL;

  key_size_t key_size = get_key_size();
  if (key_size == 0)
  {
    /* User canceled this operation */
    return;
  }

  pass_data = create_pass_struct();

  WINDOW* window = newwin(0, 0, 0, 0);

  echo();
  wprintw(window, "Username: ");
  wrefresh(window);
  wgetnstr(window, pass_data->username, USERNAME_LENGHT);

  noecho();
  wprintw(window, "Password: ");
  wrefresh(window);
  wgetnstr(window, pass_data->password, PASSWORD_LENGHT);

  wclear(window);

  if (strlen(pass_data->username) == 0 ||
      strlen(pass_data->password) == 0)
  {
    wprintw(window, "Username or password can't be empty. Exit.");
    wrefresh(window);
    goto exit;
  }

  encrypted_pass = encrypt_passdata(pass_data, key_size);
  if (encrypted_pass == NULL)
  {
    wprintw(window, "Encryption error");
    wrefresh(window);
    goto exit;
  }

  wprintw(window, "Encrypted username: %s\n", encrypted_pass->username);
  wprintw(window, "Encrypted password: %s\n", encrypted_pass->password);
  wprintw(window, "Key: %s\n", encrypted_pass->key);
  wprintw(window, "IV: %s\n", encrypted_pass->iv);
  wrefresh(window);

  exit:
  mvprintw(LINES - 2, 0, "Press any key to exit");
  refresh();
  getch();

  delete_pass_struct(pass_data);
  delete_encrypted_pass_struct(encrypted_pass);
  delwin(window);
}

void menu_decrypt_clbk() 
{
  pass_t* pass_data = NULL;
  encrypted_pass_t* buffer = create_encrypted_pass_buffer();

  WINDOW* window = newwin(0, 0, 0, 0);

  echo();
  wprintw(window, "Encrypted username: ");
  wrefresh(window);
  wgetnstr(window, buffer->username, PASS_BUFFER_LEN);

  wprintw(window, "Encrypted password: ");
  wrefresh(window);
  wgetnstr(window, buffer->password, PASS_BUFFER_LEN);

  noecho();
  wprintw(window, "Key: ");
  wrefresh(window);
  wgetnstr(window, buffer->key, PASS_BUFFER_LEN);

  wprintw(window, "IV: ");
  wrefresh(window);
  wgetnstr(window, buffer->iv, PASS_BUFFER_LEN);

  if (strlen(buffer->username) == 0 ||
      strlen(buffer->password) == 0 ||
      strlen(buffer->key) == 0 ||
      strlen(buffer->iv) == 0)
  {
    wprintw(window, "You have to fill all fields. Exit.");
    wrefresh(window);
    goto exit;
  }

  pass_data = decrypt_passdata(buffer);
  if (pass_data == NULL)
  {
    wprintw(window, "Decryption error");
    wrefresh(window);
    goto exit;
  }

  wprintw(window, "Decrypted username: %s\n", pass_data->username);
  wprintw(window, "Decrypted password: %s\n", pass_data->password);
  wrefresh(window);

exit:
  mvprintw(LINES - 2, 0, "Press any key to exit");
  refresh();
  getch();

  delete_encrypted_pass_struct(buffer);
  delwin(window);
}

int menu_handler()
{
  int c;

  initscr();
  cbreak();
  noecho();
  keypad(stdscr, TRUE);

  int n_choices = ARRAY_SIZE(action_choices);
  ITEM** my_items = (ITEM **)calloc(n_choices + 1, sizeof(ITEM *));

  my_items[0] = new_item(action_choices[0], NULL);
  set_item_userptr(my_items[0], menu_encrypt_clbk);
  my_items[1] = new_item(action_choices[1], NULL);
  set_item_userptr(my_items[1], menu_decrypt_clbk);

  MENU* my_menu = new_menu((ITEM **)my_items);
  WINDOW* my_menu_win = newwin(10, 40, 0, 0);
  set_menu_win(my_menu, my_menu_win);
  set_menu_sub(my_menu, derwin(my_menu_win, 10, 40, 0, 0));

  set_menu_mark(my_menu, " * ");

  mvprintw(LINES - 2, 0, "F1 to exit");
  refresh();

  post_menu(my_menu);
  wrefresh(my_menu_win);

  while ((c = getch()) != KEY_F(1)) 
  {
    switch (c) 
    {
    case KEY_DOWN:
      menu_driver(my_menu, REQ_DOWN_ITEM);
      break;
    case KEY_UP:
      menu_driver(my_menu, REQ_UP_ITEM);
      break;
    case 10:
      {
        void (*clbk)();
        erase();
        refresh();
        ITEM* cur_item = current_item(my_menu);
        clbk = item_userptr(cur_item);
        clbk();
        goto exit;
      }
    }

    wrefresh(my_menu_win);
  }

  exit:
  free_item(my_items[0]);
  free_item(my_items[1]);
  free_menu(my_menu);
  endwin();

  return 0;
}